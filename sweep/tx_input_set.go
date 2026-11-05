package sweep

import (
	"fmt"
	"math"
	"sort"

	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/lntypes"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
)

var (
	// ErrNotEnoughInputs is returned when there are not enough wallet
	// inputs to construct a non-dust change output for an input set.
	ErrNotEnoughInputs = fmt.Errorf("not enough inputs")

	// ErrDeadlinesMismatch is returned when the deadlines of the input
	// sets do not match.
	ErrDeadlinesMismatch = fmt.Errorf("deadlines mismatch")

	// ErrDustOutput is returned when the output value is below the dust
	// limit.
	ErrDustOutput = fmt.Errorf("dust output")
)

// InputSet defines an interface that's responsible for filtering a set of
// inputs that can be swept economically.
type InputSet interface {
	// Inputs returns the set of inputs that should be used to create a tx.
	Inputs() []input.Input

	// AddWalletInputs adds wallet inputs to the set until a non-dust
	// change output can be made. Return an error if there are not enough
	// wallet inputs. startFeeRate is the fee rate the sweep transaction
	// will first be published at, and maxFeeRate is the maximum fee rate
	// the sweeper is allowed to use when fee bumping it. Both are used to
	// decide whether a wallet UTXO is economical to add.
	AddWalletInputs(wallet Wallet, startFeeRate,
		maxFeeRate chainfee.SatPerKWeight) error

	// NeedWalletInput returns true if the input set needs more wallet
	// inputs.
	NeedWalletInput() bool

	// DeadlineHeight returns an absolute block height to express the
	// time-sensitivity of the input set. The outputs from a force close tx
	// have different time preferences:
	// - to_local: no time pressure as it can only be swept by us.
	// - first level outgoing HTLC: must be swept before its corresponding
	//   incoming HTLC's CLTV is reached.
	// - first level incoming HTLC: must be swept before its CLTV is
	//   reached.
	// - second level HTLCs: no time pressure.
	// - anchor: for CPFP-purpose anchor, it must be swept before any of
	//   the above CLTVs is reached. For non-CPFP purpose anchor, there's
	//   no time pressure.
	DeadlineHeight() int32

	// Budget givens the total amount that can be used as fees by this
	// input set.
	Budget() btcutil.Amount

	// StartingFeeRate returns the max starting fee rate found in the
	// inputs.
	StartingFeeRate() fn.Option[chainfee.SatPerKWeight]

	// Immediate returns a boolean to indicate whether the tx made from
	// this input set should be published immediately.
	//
	// TODO(yy): create a new method `Params` to combine the informational
	// methods DeadlineHeight, Budget, StartingFeeRate and Immediate.
	Immediate() bool
}

// createWalletTxInput converts a wallet utxo into an object that can be added
// to the other inputs to sweep.
func createWalletTxInput(utxo *lnwallet.Utxo) (input.Input, error) {
	signDesc := &input.SignDescriptor{
		Output: &wire.TxOut{
			PkScript: utxo.PkScript,
			Value:    int64(utxo.Value),
		},
		HashType: txscript.SigHashAll,
	}

	var witnessType input.WitnessType
	switch utxo.AddressType {
	case lnwallet.WitnessPubKey:
		witnessType = input.WitnessKeyHash
	case lnwallet.NestedWitnessPubKey:
		witnessType = input.NestedWitnessKeyHash
	case lnwallet.TaprootPubkey:
		witnessType = input.TaprootPubKeySpend
		signDesc.HashType = txscript.SigHashDefault
	default:
		return nil, fmt.Errorf("unknown address type %v",
			utxo.AddressType)
	}

	// A height hint doesn't need to be set, because we don't monitor these
	// inputs for spend.
	heightHint := uint32(0)

	return input.NewBaseInput(
		&utxo.OutPoint, witnessType, signDesc, heightHint,
	), nil
}

// BudgetInputSet implements the interface `InputSet`. It takes a list of
// pending inputs which share the same deadline height and groups them into a
// set conditionally based on their economical values.
type BudgetInputSet struct {
	// inputs is the set of inputs that have been added to the set after
	// considering their economical contribution.
	inputs []*SweeperInput

	// deadlineHeight is the height which the inputs in this set must be
	// confirmed by.
	deadlineHeight int32

	// extraBudget is a value that should be allocated to sweep the given
	// set of inputs. This can be used to add extra funds to the sweep
	// transaction, for example to cover fees for additional outputs of
	// custom channels.
	extraBudget btcutil.Amount
}

// Compile-time constraint to ensure budgetInputSet implements InputSet.
var _ InputSet = (*BudgetInputSet)(nil)

// errEmptyInputs is returned when the input slice is empty.
var errEmptyInputs = fmt.Errorf("inputs slice is empty")

const (
	// maxStandardTxWeight is the maximum weight a transaction may have to
	// be accepted into the mempool under the default standardness policy.
	// It mirrors btcd's unexported maxStandardTxWeight.
	maxStandardTxWeight = lntypes.WeightUnit(400_000)

	// sweepTxWeightMargin is the weight reserved for transaction outputs
	// that are not yet known when wallet inputs are selected, such as
	// extra outputs added by the aux sweeper.
	sweepTxWeightMargin = lntypes.WeightUnit(1_000)

	// maxWalletInputs is the max number of wallet inputs added to a single
	// input set, matching the default max number of inputs the aggregator
	// puts into a set. Together with the weight limit, it bounds the size
	// of a sweep funded by a wallet holding many small UTXOs.
	maxWalletInputs = 100
)

// validateInputs is used when creating new BudgetInputSet to ensure there are
// no duplicate inputs and they all share the same deadline heights, if set.
func validateInputs(inputs []SweeperInput, deadlineHeight int32) error {
	// Sanity check the input slice to ensure it's non-empty.
	if len(inputs) == 0 {
		return errEmptyInputs
	}

	// inputDeadline tracks the input's deadline height. It will be updated
	// if the input has a different deadline than the specified
	// deadlineHeight.
	inputDeadline := deadlineHeight

	// dedupInputs is a set used to track unique outpoints of the inputs.
	dedupInputs := fn.NewSet(
		// Iterate all the inputs and map the function.
		fn.Map(inputs, func(inp SweeperInput) wire.OutPoint {
			// If the input has a deadline height, we'll check if
			// it's the same as the specified.
			inp.params.DeadlineHeight.WhenSome(func(h int32) {
				// Exit early if the deadlines matched.
				if h == deadlineHeight {
					return
				}

				// Update the deadline height if it's
				// different.
				inputDeadline = h
			})

			return inp.OutPoint()
		})...,
	)

	// Make sure the inputs share the same deadline height when there is
	// one.
	if inputDeadline != deadlineHeight {
		return fmt.Errorf("input deadline height not matched: want "+
			"%d, got %d", deadlineHeight, inputDeadline)
	}

	// Provide a defensive check to ensure that we don't have any duplicate
	// inputs within the set.
	if len(dedupInputs) != len(inputs) {
		return fmt.Errorf("duplicate inputs")
	}

	return nil
}

// NewBudgetInputSet creates a new BudgetInputSet.
func NewBudgetInputSet(inputs []SweeperInput, deadlineHeight int32,
	auxSweeper fn.Option[AuxSweeper]) (*BudgetInputSet, error) {

	// Validate the supplied inputs.
	if err := validateInputs(inputs, deadlineHeight); err != nil {
		return nil, err
	}

	bi := &BudgetInputSet{
		deadlineHeight: deadlineHeight,
		inputs:         make([]*SweeperInput, 0, len(inputs)),
	}

	for _, input := range inputs {
		bi.addInput(input)
	}

	log.Tracef("Created %v", bi.String())

	// Attach an optional budget. This will be a no-op if the auxSweeper
	// is not set.
	if err := bi.attachExtraBudget(auxSweeper); err != nil {
		return nil, err
	}

	return bi, nil
}

// attachExtraBudget attaches an extra budget to the input set, if the passed
// aux sweeper is set.
func (b *BudgetInputSet) attachExtraBudget(s fn.Option[AuxSweeper]) error {
	extraBudget, err := fn.MapOptionZ(
		s, func(aux AuxSweeper) fn.Result[btcutil.Amount] {
			return aux.ExtraBudgetForInputs(b.Inputs())
		},
	).Unpack()
	if err != nil {
		return err
	}

	b.extraBudget = extraBudget

	return nil
}

// String returns a human-readable description of the input set.
func (b *BudgetInputSet) String() string {
	inputsDesc := ""
	for _, input := range b.inputs {
		inputsDesc += fmt.Sprintf("\n%v", input)
	}

	return fmt.Sprintf("BudgetInputSet(budget=%v, deadline=%v, "+
		"inputs=[%v])", b.Budget(), b.DeadlineHeight(), inputsDesc)
}

// addInput adds an input to the input set.
func (b *BudgetInputSet) addInput(input SweeperInput) {
	b.inputs = append(b.inputs, &input)
}

// addWalletInput takes a wallet UTXO and adds it as an input to be used as
// budget for the input set.
func (b *BudgetInputSet) addWalletInput(utxo *lnwallet.Utxo) error {
	input, err := createWalletTxInput(utxo)
	if err != nil {
		return err
	}

	pi := SweeperInput{
		Input: input,
		params: Params{
			DeadlineHeight: fn.Some(b.deadlineHeight),
		},
	}
	b.addInput(pi)

	log.Debugf("Added wallet input to input set: op=%v, amt=%v",
		pi.OutPoint(), utxo.Value)

	return nil
}

// NeedWalletInput returns true if the input set needs more wallet inputs.
//
// A set may need wallet inputs when it has a required output or its total
// value cannot cover its total budget.
func (b *BudgetInputSet) NeedWalletInput() bool {
	var (
		// budgetNeeded is the amount that needs to be covered from
		// other inputs. We start at the value of the extra budget,
		// which might be needed for custom channels that add extra
		// outputs.
		budgetNeeded = b.extraBudget

		// budgetBorrowable is the amount that can be borrowed from
		// other inputs.
		budgetBorrowable btcutil.Amount
	)

	for _, inp := range b.inputs {
		// If this input has a required output, we can assume it's a
		// second-level htlc txns input. Although this input must have
		// a value that can cover its budget, it cannot be used to pay
		// fees. Instead, we need to borrow budget from other inputs to
		// make the sweep happen. Once swept, the input value will be
		// credited to the wallet.
		if inp.RequiredTxOut() != nil {
			budgetNeeded += inp.params.Budget
			continue
		}

		// Get the amount left after covering the input's own budget.
		// This amount can then be lent to the above input. For a wallet
		// input, its `Budget` is set to zero, which means the whole
		// input can be borrowed to cover the budget.
		budget := inp.params.Budget
		output := btcutil.Amount(inp.SignDesc().Output.Value)
		budgetBorrowable += output - budget

		// If the input's budget is not even covered by itself, we need
		// to borrow outputs from other inputs.
		if budgetBorrowable < 0 {
			log.Tracef("Input %v specified a budget that exceeds "+
				"its output value: %v > %v", inp, budget,
				output)
		}
	}

	log.Debugf("NeedWalletInput: budgetNeeded=%v, budgetBorrowable=%v",
		budgetNeeded, budgetBorrowable)

	// If we don't have enough extra budget to borrow, we need wallet
	// inputs.
	return budgetBorrowable < budgetNeeded
}

// hasNormalInput return a bool to indicate whether there exists an input that
// doesn't require a TxOut. When an input has no required outputs, it's either a
// wallet input, or an input we want to sweep.
func (b *BudgetInputSet) hasNormalInput() bool {
	for _, inp := range b.inputs {
		if inp.RequiredTxOut() != nil {
			continue
		}

		return true
	}

	return false
}

// walletCandidate is a wallet UTXO considered for a budget input set, along
// with the weight it adds to the sweep transaction.
type walletCandidate struct {
	utxo   *lnwallet.Utxo
	input  input.Input
	weight lntypes.WeightUnit
}

// density returns the candidate's value per weight unit, which is the highest
// fee rate at which the candidate still pays for its own input weight.
func (c walletCandidate) density() chainfee.SatPerKWeight {
	return chainfee.NewSatPerKWeight(c.utxo.Value, c.weight)
}

// AddWalletInputs adds wallet inputs to the set until the specified budget is
// met. When sweeping inputs with required outputs, although there's budget
// specified, it cannot be directly spent from these required outputs. Instead,
// we need to borrow budget from other inputs to make the sweep happen.
// There are two sources to borrow from: 1) other inputs, 2) wallet utxos. If
// we are calling this method, it means other inputs cannot cover the specified
// budget, so we need to borrow from wallet utxos.
//
// Wallet UTXOs are considered in order of value per weight unit, highest
// first, and a UTXO is only added if it raises the highest fee rate the sweep
// can be published at. That rate is the funds available for fees divided by
// the transaction weight, capped by the budget and maxFeeRate. A UTXO is also
// never added if it cannot pay for its own input weight at startFeeRate, the
// fee rate the first broadcast will use, as it cannot help get the sweep
// published. This keeps the selection small and prevents UTXOs that are worth
// less than the fee to spend them, such as dust, from being swept.
//
// Return an error if there are not enough wallet inputs, and the budget set is
// set to its initial state by removing any wallet inputs added.
//
// NOTE: must be called with the wallet lock held via `WithCoinSelectLock`.
func (b *BudgetInputSet) AddWalletInputs(wallet Wallet, startFeeRate,
	maxFeeRate chainfee.SatPerKWeight) error {

	// Retrieve wallet utxos. Only consider confirmed utxos to prevent
	// problems around RBF rules for unconfirmed inputs. This currently
	// ignores the configured coin selection strategy.
	utxos, err := wallet.ListUnspentWitnessFromDefaultAccount(
		1, math.MaxInt32,
	)
	if err != nil {
		return fmt.Errorf("list unspent witness: %w", err)
	}

	// Seed a weight estimate with the set's existing inputs and reserve an
	// output for the sweep destination. This keeps the transaction below
	// the standardness weight limit as wallet inputs are added.
	//
	// The estimator's fee rate only decides which unconfirmed parents are
	// counted, as it skips parents paying at least that rate. We use
	// maxFeeRate rather than startFeeRate, since fee bumps can raise the
	// child's fee rate up to maxFeeRate, at which point any parent paying
	// less still needs the CPFP and its weight must shape the selection.
	estimator := newWeightEstimator(maxFeeRate, 0)
	for _, inp := range b.inputs {
		if err := estimator.add(inp.Input); err != nil {
			// Skip inputs that cannot be weighted, the same way the
			// tx generator treats them. They are accounted for by
			// the weight margin.
			log.Errorf("Failed to get weight estimate for "+
				"input=%v: %v", inp.OutPoint(), err)

			continue
		}

		if txOut := inp.RequiredTxOut(); txOut != nil {
			estimator.addOutput(txOut)
		}
	}
	estimator.addP2TROutput()

	// Measure the weight each UTXO adds to the transaction, without
	// mutating the estimator.
	candidates := make([]walletCandidate, 0, len(utxos))
	for _, utxo := range utxos {
		inp, err := createWalletTxInput(utxo)
		if err != nil {
			return err
		}

		trial := estimator.estimator
		err = inp.WitnessType().AddWeightEstimation(&trial)
		if err != nil {
			return fmt.Errorf("estimate wallet input weight: %w",
				err)
		}

		candidates = append(candidates, walletCandidate{
			utxo:   utxo,
			input:  inp,
			weight: trial.Weight() - estimator.weight(),
		})
	}

	// Consider the UTXOs with the highest value per weight unit first. For
	// UTXOs of the same address type this is largest first, so the fewest
	// inputs cover the budget.
	//
	// TODO(yy): add more choices to CoinSelectionStrategy and use the
	// configured value here.
	sort.SliceStable(candidates, func(i, j int) bool {
		return candidates[i].density() > candidates[j].density()
	})

	// spendable tracks the value of the set's inputs that can pay fees.
	// It's only needed when there are wallet UTXOs to consider.
	var spendable btcutil.Amount
	if len(candidates) > 0 {
		spendable = b.spendableAmt()
	}

	maxWeight := maxStandardTxWeight - sweepTxWeightMargin

	var (
		skipped int
		added   int
	)
	for _, c := range candidates {
		// Stop adding wallet inputs once the max number of wallet
		// inputs has been reached.
		if added >= maxWalletInputs {
			log.Warnf("Stopped adding wallet inputs: reached max "+
				"of %v wallet inputs", maxWalletInputs)

			break
		}

		weight := estimator.weight()

		// Stop adding wallet inputs once the transaction would exceed
		// the standardness weight limit.
		if weight+c.weight > maxWeight {
			log.Warnf("Stopped adding wallet inputs: tx weight %v "+
				"would exceed %v", weight+c.weight, maxWeight)

			break
		}

		// Only add the UTXO if it raises the fee rate the sweep can
		// reach, and pays for itself at the starting fee rate.
		minRate := b.walletInputFeeRate(
			weight, spendable, estimator.parentsFee,
			estimator.parentsWeight, startFeeRate, maxFeeRate,
		)
		if c.density() <= minRate {
			skipped++

			continue
		}

		if err := estimator.add(c.input); err != nil {
			return fmt.Errorf("estimate wallet input weight: %w",
				err)
		}

		if err := b.addWalletInput(c.utxo); err != nil {
			return err
		}
		spendable += c.utxo.Value
		added++

		// Return if we've reached the minimum output amount.
		if !b.NeedWalletInput() {
			return nil
		}
	}

	if skipped > 0 {
		log.Debugf("Skipped %v wallet utxos that cannot raise the fee "+
			"rate of the sweep", skipped)
	}

	// Exit if there are no inputs can contribute to the fees.
	if !b.hasNormalInput() {
		return ErrNotEnoughInputs
	}

	// If there's at least one input that can contribute to fees, we allow
	// the sweep to continue, even though the full budget can't be met.
	// Maybe later more wallet inputs will become available and we can add
	// them if needed.
	budget := b.Budget()
	total, spendable := b.inputAmts()
	log.Warnf("Not enough wallet UTXOs: need budget=%v, has spendable=%v, "+
		"total=%v, missing at least %v, sweeping anyway...", budget,
		spendable, total, budget-spendable)

	return nil
}

// walletInputFeeRate returns the fee rate a wallet UTXO must exceed, per
// weight unit it adds, to be worth adding to a set of the given weight whose
// inputs that can pay fees are worth spendable.
//
// The fee bumper can raise the sweep's fee rate up to the budget divided by
// the transaction weight, capped by maxFeeRate, but only as far as the
// set's spendable funds allow. A UTXO raises that reachable fee rate only if
// its value per weight unit exceeds it. The rate is floored at the starting
// fee rate, capped the same way, as a UTXO that cannot pay for itself there
// cannot help get the sweep published.
//
// When the sweep is a CPFP child of unconfirmed parents, what matters is the
// fee rate of the whole package, as the parents usually dominate its weight.
// The reachable rate is then the child's highest affordable fee plus the
// parents' fee, divided by the combined weight. This rate is far lower than
// the child's own fee rate, so UTXOs that raise the package's fee rate are
// still added even when they would lower the child's.
func (b *BudgetInputSet) walletInputFeeRate(weight lntypes.WeightUnit,
	spendable, parentsFee btcutil.Amount, parentsWeight lntypes.WeightUnit,
	startFeeRate,
	maxFeeRate chainfee.SatPerKWeight) chainfee.SatPerKWeight {

	// The highest fee rate the budget allows.
	ceiling := chainfee.NewSatPerKWeight(b.Budget(), weight)
	if ceiling > maxFeeRate {
		ceiling = maxFeeRate
	}

	// The highest fee rate the set's spendable funds can pay for.
	reachable := chainfee.NewSatPerKWeight(spendable, weight)
	if reachable > ceiling {
		reachable = ceiling
	}

	// For a CPFP child, measure the reachable rate over the package. The
	// fee bumper charges the child's fee rate on the child's weight only,
	// so the child's highest fee is capped the same way as above. If the
	// parents pay more than the child, miners take them on their own and
	// then judge the child by its own fee rate, so we use the lower of the
	// two rates.
	if parentsWeight > 0 {
		childFee := min(spendable, ceiling.FeeForWeight(weight))
		pkgRate := chainfee.NewSatPerKWeight(
			childFee+parentsFee, weight+parentsWeight,
		)
		reachable = min(reachable, pkgRate)
	}

	// The fee rate the first broadcast will use.
	start := startFeeRate
	if start > ceiling {
		start = ceiling
	}

	if reachable > start {
		return reachable
	}

	return start
}

// spendableAmt returns the total value of the set's inputs that can pay fees,
// which are the inputs without a required output.
func (b *BudgetInputSet) spendableAmt() btcutil.Amount {
	var spendable btcutil.Amount
	for _, inp := range b.inputs {
		if inp.RequiredTxOut() != nil {
			continue
		}

		spendable += btcutil.Amount(inp.SignDesc().Output.Value)
	}

	return spendable
}

// Budget returns the total budget of the set.
//
// NOTE: part of the InputSet interface.
func (b *BudgetInputSet) Budget() btcutil.Amount {
	budget := btcutil.Amount(0)
	for _, input := range b.inputs {
		budget += input.params.Budget
	}

	// We'll also tack on the extra budget which will eventually be
	// accounted for by the wallet txns when we're broadcasting.
	return budget + b.extraBudget
}

// DeadlineHeight returns the deadline height of the set.
//
// NOTE: part of the InputSet interface.
func (b *BudgetInputSet) DeadlineHeight() int32 {
	return b.deadlineHeight
}

// Inputs returns the inputs that should be used to create a tx.
//
// NOTE: part of the InputSet interface.
func (b *BudgetInputSet) Inputs() []input.Input {
	inputs := make([]input.Input, 0, len(b.inputs))
	for _, inp := range b.inputs {
		inputs = append(inputs, inp.Input)
	}

	return inputs
}

// inputAmts returns two values for the set - the total input amount, and the
// spendable amount. Only the spendable amount can be used to pay the fees.
func (b *BudgetInputSet) inputAmts() (btcutil.Amount, btcutil.Amount) {
	var (
		totalAmt     btcutil.Amount
		spendableAmt btcutil.Amount
	)

	for _, inp := range b.inputs {
		output := btcutil.Amount(inp.SignDesc().Output.Value)
		totalAmt += output

		if inp.RequiredTxOut() != nil {
			continue
		}

		spendableAmt += output
	}

	return totalAmt, spendableAmt
}

// StartingFeeRate returns the max starting fee rate found in the inputs.
//
// NOTE: part of the InputSet interface.
func (b *BudgetInputSet) StartingFeeRate() fn.Option[chainfee.SatPerKWeight] {
	maxFeeRate := chainfee.SatPerKWeight(0)
	startingFeeRate := fn.None[chainfee.SatPerKWeight]()

	for _, inp := range b.inputs {
		feerate := inp.params.StartingFeeRate.UnwrapOr(0)
		if feerate > maxFeeRate {
			maxFeeRate = feerate
			startingFeeRate = fn.Some(maxFeeRate)
		}
	}

	return startingFeeRate
}

// Immediate returns whether the inputs should be swept immediately.
//
// NOTE: part of the InputSet interface.
func (b *BudgetInputSet) Immediate() bool {
	for _, inp := range b.inputs {
		// As long as one of the inputs is immediate, the whole set is
		// immediate.
		if inp.params.Immediate {
			return true
		}
	}

	return false
}
