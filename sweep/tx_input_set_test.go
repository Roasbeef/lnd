package sweep

import (
	"errors"
	"math"
	"testing"

	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/lntypes"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	"github.com/stretchr/testify/require"
)

// createP2WKHInput returns a P2WKH test input with the specified amount.
func createP2WKHInput(amt btcutil.Amount) input.Input {
	input := createTestInput(int64(amt), input.WitnessKeyHash)
	return &input
}

// testMaxFeeRate is the default max fee rate of the sweeper, used by the
// wallet input tests.
var testMaxFeeRate = DefaultMaxFeeRate.FeePerKWeight()

// TestNewBudgetInputSet checks `NewBudgetInputSet` correctly validates the
// supplied inputs and returns the error.
func TestNewBudgetInputSet(t *testing.T) {
	t.Parallel()

	rt := require.New(t)

	// Pass an empty slice and expect an error.
	set, err := NewBudgetInputSet(
		[]SweeperInput{}, testHeight, fn.None[AuxSweeper](),
	)
	rt.ErrorContains(err, "inputs slice is empty")
	rt.Nil(set)

	// Create two inputs with different deadline heights.
	inp0 := createP2WKHInput(1000)
	inp1 := createP2WKHInput(1000)
	inp2 := createP2WKHInput(1000)
	input0 := SweeperInput{
		Input: inp0,
		params: Params{
			Budget:         100,
			DeadlineHeight: fn.None[int32](),
		},
	}
	input1 := SweeperInput{
		Input: inp1,
		params: Params{
			Budget:         100,
			DeadlineHeight: fn.Some(int32(1)),
		},
	}
	input2 := SweeperInput{
		Input: inp2,
		params: Params{
			Budget:         100,
			DeadlineHeight: fn.Some(int32(2)),
		},
	}
	input3 := SweeperInput{
		Input: inp2,
		params: Params{
			Budget:         100,
			DeadlineHeight: fn.Some(testHeight),
		},
	}

	// Pass a slice of inputs with different deadline heights.
	set, err = NewBudgetInputSet(
		[]SweeperInput{input1, input2}, testHeight,
		fn.None[AuxSweeper](),
	)
	rt.ErrorContains(err, "input deadline height not matched")
	rt.Nil(set)

	// Pass a slice of inputs that only one input has the deadline height,
	// but it has a different value than the specified testHeight.
	set, err = NewBudgetInputSet(
		[]SweeperInput{input0, input2}, testHeight,
		fn.None[AuxSweeper](),
	)
	rt.ErrorContains(err, "input deadline height not matched")
	rt.Nil(set)

	// Pass a slice of inputs that are duplicates.
	set, err = NewBudgetInputSet(
		[]SweeperInput{input3, input3}, testHeight,
		fn.None[AuxSweeper](),
	)
	rt.ErrorContains(err, "duplicate inputs")
	rt.Nil(set)

	// Pass a slice of inputs that only one input has the deadline height.
	set, err = NewBudgetInputSet(
		[]SweeperInput{input0, input3}, testHeight,
		fn.None[AuxSweeper](),
	)
	rt.NoError(err)
	rt.NotNil(set)
}

// TestBudgetInputSetAddInput checks that `addInput` correctly updates the
// budget of the input set.
func TestBudgetInputSetAddInput(t *testing.T) {
	t.Parallel()

	// Create a testing input with a budget of 100 satoshis.
	input := createP2WKHInput(1000)
	pi := &SweeperInput{
		Input: input,
		params: Params{
			Budget: 100,
		},
	}

	// Initialize an input set, which adds the above input.
	set, err := NewBudgetInputSet(
		[]SweeperInput{*pi}, testHeight, fn.None[AuxSweeper](),
	)
	require.NoError(t, err)

	// Add the input to the set again.
	set.addInput(*pi)

	// The set should now have two inputs.
	require.Len(t, set.inputs, 2)
	require.Equal(t, pi, set.inputs[0])
	require.Equal(t, pi, set.inputs[1])

	// The set should have a budget of 200 satoshis.
	require.Equal(t, btcutil.Amount(200), set.Budget())
}

// TestAddWalletInput asserts `addWalletInput` successfully converts a wallet
// UTXO into a `SweeperInput` with the correct deadline.
func TestAddWalletInput(t *testing.T) {
	t.Parallel()

	// Create a testing deadline.
	deadline := int32(1000)

	// Initialize an empty input set.
	set := &BudgetInputSet{
		deadlineHeight: deadline,
	}

	// Create an utxo with unknown address type to trigger an error.
	utxo := &lnwallet.Utxo{
		AddressType: lnwallet.UnknownAddressType,
	}

	// Check that the error is returned from addWalletInput.
	err := set.addWalletInput(utxo)
	require.Error(t, err)

	// Create a wallet utxo.
	utxo = &lnwallet.Utxo{
		AddressType: lnwallet.WitnessPubKey,
		Value:       1000,
	}

	// Check that no error is returned from addWalletInput.
	err = set.addWalletInput(utxo)
	require.NoError(t, err)

	// Check the input has been added to the set.
	require.Len(t, set.inputs, 1)

	// Assert the wallet input is added using the set's deadline.
	inp := set.inputs[0]
	require.True(t, inp.params.DeadlineHeight.IsSome())
	require.Equal(t, deadline, inp.params.DeadlineHeight.UnsafeFromSome())
}

// TestNeedWalletInput checks that NeedWalletInput correctly determines if a
// wallet input is needed.
func TestNeedWalletInput(t *testing.T) {
	t.Parallel()

	// Create a mock input that doesn't have required outputs.
	mockInput := &input.MockInput{}
	mockInput.On("RequiredTxOut").Return(nil)
	mockInput.On("OutPoint").Return(wire.OutPoint{Hash: chainhash.Hash{1}})
	defer mockInput.AssertExpectations(t)

	// Create a mock input that has required outputs.
	mockInputRequireOutput := &input.MockInput{}
	mockInputRequireOutput.On("RequiredTxOut").Return(&wire.TxOut{})
	mockInputRequireOutput.On("OutPoint").Return(
		wire.OutPoint{Hash: chainhash.Hash{2}},
	)
	defer mockInputRequireOutput.AssertExpectations(t)

	// We now create two pending inputs each has a budget of 100 satoshis.
	const budget = 100

	// Create the pending input that doesn't have a required output.
	piBudget := SweeperInput{
		Input:  mockInput,
		params: Params{Budget: budget},
	}

	// Create the pending input that has a required output.
	piRequireOutput := SweeperInput{
		Input:  mockInputRequireOutput,
		params: Params{Budget: budget},
	}

	testCases := []struct {
		name        string
		setupInputs func() []SweeperInput
		extraBudget btcutil.Amount
		need        bool
		err         error
	}{
		{
			// When there are no pending inputs, we won't need a
			// wallet input. Technically this is be an invalid
			// state.
			name: "no inputs",
			setupInputs: func() []SweeperInput {
				return nil
			},
			need: false,
			err:  errEmptyInputs,
		},
		{
			// When there's no required output, we don't need a
			// wallet input.
			name: "no required outputs",
			setupInputs: func() []SweeperInput {
				// Create a sign descriptor to be used in the
				// pending input when calculating budgets can
				// be borrowed.
				sd := &input.SignDescriptor{
					Output: &wire.TxOut{
						Value: budget,
					},
				}
				mockInput.On("SignDesc").Return(sd).Once()

				return []SweeperInput{piBudget}
			},
			need: false,
		},
		{
			// When there's no required normal outputs, but an extra
			// budget from custom channels, we will need a wallet
			// input.
			name: "no required normal outputs but extra budget",
			setupInputs: func() []SweeperInput {
				// Create a sign descriptor to be used in the
				// pending input when calculating budgets can
				// be borrowed.
				sd := &input.SignDescriptor{
					Output: &wire.TxOut{
						Value: budget,
					},
				}
				mockInput.On("SignDesc").Return(sd).Once()

				return []SweeperInput{piBudget}
			},
			extraBudget: 1000,
			need:        true,
		},
		{
			// When the output value cannot cover the budget, we
			// need a wallet input.
			name: "output value cannot cover budget",
			setupInputs: func() []SweeperInput {
				// Create a sign descriptor to be used in the
				// pending input when calculating budgets can
				// be borrowed.
				sd := &input.SignDescriptor{
					Output: &wire.TxOut{
						Value: budget - 1,
					},
				}

				mockInput.On("SignDesc").Return(sd).Once()
				// These two methods are only invoked when the
				// unit test is running with a logger.
				mockInput.On("OutPoint").Return(
					wire.OutPoint{Hash: chainhash.Hash{1}},
				).Maybe()
				mockInput.On("WitnessType").Return(
					input.CommitmentAnchor,
				).Maybe()

				return []SweeperInput{piBudget}
			},
			need: true,
		},
		{
			// When there's only inputs that require outputs, we
			// need wallet inputs.
			name: "only required outputs",
			setupInputs: func() []SweeperInput {
				return []SweeperInput{piRequireOutput}
			},
			need: true,
		},
		{
			// When there's a mix of inputs, but the borrowable
			// budget cannot cover the required, we need a wallet
			// input.
			name: "not enough budget to be borrowed",
			setupInputs: func() []SweeperInput {
				// Create a sign descriptor to be used in the
				// pending input when calculating budgets can
				// be borrowed.
				//
				// NOTE: the value is exactly the same as the
				// budget so we can't borrow any more.
				sd := &input.SignDescriptor{
					Output: &wire.TxOut{
						Value: budget,
					},
				}
				mockInput.On("SignDesc").Return(sd).Once()

				return []SweeperInput{
					piBudget, piRequireOutput,
				}
			},
			need: true,
		},
		{
			// When there's a mix of inputs, and the budget can be
			// borrowed covers the required, we don't need wallet
			// inputs.
			name: "enough budget to be borrowed",
			setupInputs: func() []SweeperInput {
				// Create a sign descriptor to be used in the
				// pending input when calculating budgets can
				// be borrowed.
				//
				// NOTE: the value is exactly the same as the
				// budget so we can't borrow any more.
				sd := &input.SignDescriptor{
					Output: &wire.TxOut{
						Value: budget * 2,
					},
				}
				mockInput.On("SignDesc").Return(sd).Once()
				piBudget.Input = mockInput

				return []SweeperInput{
					piBudget, piRequireOutput,
				}
			},
			need: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup testing inputs.
			inputs := tc.setupInputs()

			// If an extra budget is set, then we'll update the mock
			// to expect the extra budget.
			mockAuxSweeper := &MockAuxSweeper{}
			mockAuxSweeper.On("ExtraBudgetForInputs").Return(
				fn.Ok(tc.extraBudget),
			)

			// Initialize an input set, which adds the testing
			// inputs.
			set, err := NewBudgetInputSet(
				inputs, 0, fn.Some[AuxSweeper](mockAuxSweeper),
			)
			if err != nil {
				require.ErrorIs(t, err, tc.err)
				return
			}

			result := set.NeedWalletInput()

			require.Equal(t, tc.need, result)
			mockAuxSweeper.AssertExpectations(t)
		})
	}
}

// TestAddWalletInputsReturnErr tests the three possible errors returned from
// AddWalletInputs:
// - error from ListUnspentWitnessFromDefaultAccount.
// - error from createWalletTxInput.
// - error when wallet doesn't have utxos.
func TestAddWalletInputsReturnErr(t *testing.T) {
	t.Parallel()

	wallet := &MockWallet{}
	defer wallet.AssertExpectations(t)

	// Initialize an empty input set.
	set := &BudgetInputSet{}

	// Specify the min and max confs used in
	// ListUnspentWitnessFromDefaultAccount.
	min, max := int32(1), int32(math.MaxInt32)

	// Mock the wallet to return an error.
	dummyErr := errors.New("dummy error")
	wallet.On("ListUnspentWitnessFromDefaultAccount",
		min, max).Return(nil, dummyErr).Once()

	// Check that the error is returned from
	// ListUnspentWitnessFromDefaultAccount.
	err := set.AddWalletInputs(
		wallet, chainfee.FeePerKwFloor, testMaxFeeRate,
	)
	require.ErrorIs(t, err, dummyErr)

	// Create an utxo with unknown address type to trigger an error.
	utxo := &lnwallet.Utxo{
		AddressType: lnwallet.UnknownAddressType,
	}

	// Mock the wallet to return the above utxo.
	wallet.On("ListUnspentWitnessFromDefaultAccount",
		min, max).Return([]*lnwallet.Utxo{utxo}, nil).Once()

	// Check that the error is returned from createWalletTxInput.
	err = set.AddWalletInputs(
		wallet, chainfee.FeePerKwFloor, testMaxFeeRate,
	)
	require.Error(t, err)

	// Mock the wallet to return empty utxos.
	wallet.On("ListUnspentWitnessFromDefaultAccount",
		min, max).Return([]*lnwallet.Utxo{}, nil).Once()

	// Check that the error is returned from not having wallet inputs.
	err = set.AddWalletInputs(
		wallet, chainfee.FeePerKwFloor, testMaxFeeRate,
	)
	require.ErrorIs(t, err, ErrNotEnoughInputs)
}

// TestAddWalletInputsNotEnoughInputs checks that when there are not enough
// wallet utxos, no error is returned as long as the wallet is not empty.
func TestAddWalletInputsNotEnoughInputs(t *testing.T) {
	t.Parallel()

	wallet := &MockWallet{}
	defer wallet.AssertExpectations(t)

	// Specify the min and max confs used in
	// ListUnspentWitnessFromDefaultAccount.
	min, max := int32(1), int32(math.MaxInt32)

	// Assume the desired budget is 10k satoshis.
	const budget = 10_000

	// Create a mock input that has required outputs.
	mockInput := &input.MockInput{}
	mockInput.On("RequiredTxOut").Return(&wire.TxOut{})

	// Mock methods used when weighting the input.
	mockInput.On("WitnessType").Return(input.WitnessKeyHash)
	mockInput.On("UnconfParent").Return(nil)
	defer mockInput.AssertExpectations(t)

	sd := &input.SignDescriptor{
		Output: &wire.TxOut{
			Value: budget,
		},
	}
	mockInput.On("SignDesc").Return(sd).Once()

	// Create a pending input that requires 10k satoshis.
	pi := &SweeperInput{
		Input:  mockInput,
		params: Params{Budget: budget},
	}

	// Create a wallet utxo that cannot cover the budget.
	utxo := &lnwallet.Utxo{
		AddressType: lnwallet.WitnessPubKey,
		Value:       budget - 1,
	}

	// Mock the wallet to return the above utxo.
	wallet.On("ListUnspentWitnessFromDefaultAccount",
		min, max).Return([]*lnwallet.Utxo{utxo}, nil).Once()

	// Initialize an input set with the pending input.
	set := BudgetInputSet{inputs: []*SweeperInput{pi}}

	// Add wallet inputs to the input set, which should return no error
	// although the wallet cannot cover the budget.
	err := set.AddWalletInputs(
		wallet, chainfee.FeePerKwFloor, testMaxFeeRate,
	)
	require.NoError(t, err)

	// Check that the budget set is updated.
	require.Len(t, set.inputs, 2)
}

// TestAddWalletInputsEmptyWalletSuccess checks that when the wallet is empty,
// if there is a normal input, no error is returned.
func TestAddWalletInputsEmptyWalletSuccess(t *testing.T) {
	t.Parallel()

	wallet := &MockWallet{}
	defer wallet.AssertExpectations(t)

	// Specify the min and max confs used in
	// ListUnspentWitnessFromDefaultAccount.
	minConf, maxConf := int32(1), int32(math.MaxInt32)

	// Assume the desired budget is 10k satoshis.
	const budget = 10_000

	// Create a mock input that has required outputs.
	mockInput1 := &input.MockInput{}
	defer mockInput1.AssertExpectations(t)

	mockInput1.On("RequiredTxOut").Return(&wire.TxOut{})

	// Mock methods used when weighting the input.
	mockInput1.On("WitnessType").Return(input.WitnessKeyHash)
	mockInput1.On("UnconfParent").Return(nil)

	sd := &input.SignDescriptor{
		Output: &wire.TxOut{
			Value: budget,
		},
	}
	mockInput1.On("SignDesc").Return(sd).Once()

	// Create a pending input that requires 10k satoshis.
	pi1 := &SweeperInput{
		Input:  mockInput1,
		params: Params{Budget: budget},
	}

	// Create a mock input that doesn't require outputs.
	mockInput2 := &input.MockInput{}
	defer mockInput2.AssertExpectations(t)

	mockInput2.On("RequiredTxOut").Return(nil)

	// Mock methods used when weighting the input.
	mockInput2.On("WitnessType").Return(input.WitnessKeyHash)
	mockInput2.On("UnconfParent").Return(nil)

	sd2 := &input.SignDescriptor{
		Output: &wire.TxOut{
			Value: budget,
		},
	}
	mockInput2.On("SignDesc").Return(sd2).Once()

	// Create a pending input that requires 10k satoshis.
	pi2 := &SweeperInput{
		Input:  mockInput2,
		params: Params{Budget: budget},
	}

	// Mock the wallet to return empty utxos.
	wallet.On("ListUnspentWitnessFromDefaultAccount",
		minConf, maxConf).Return([]*lnwallet.Utxo{}, nil).Once()

	// Initialize an input set with the pending inputs.
	set := BudgetInputSet{inputs: []*SweeperInput{pi1, pi2}}

	// Add wallet inputs to the input set, which should return no error
	// although the wallet is empty.
	err := set.AddWalletInputs(
		wallet, chainfee.FeePerKwFloor, testMaxFeeRate,
	)
	require.NoError(t, err)
}

// TestAddWalletInputsLargestFirst checks that wallet inputs are selected
// largest first so the fewest inputs cover the budget.
func TestAddWalletInputsLargestFirst(t *testing.T) {
	t.Parallel()

	wallet := &MockWallet{}
	defer wallet.AssertExpectations(t)

	const (
		budget  = 10_000
		numDust = 100
	)

	// Create an input whose required output prevents it from paying its own
	// budget.
	mockInput := &input.MockInput{}
	mockInput.On("RequiredTxOut").Return(&wire.TxOut{})

	// Mock methods used when weighting the input.
	mockInput.On("WitnessType").Return(input.WitnessKeyHash)
	mockInput.On("UnconfParent").Return(nil)
	defer mockInput.AssertExpectations(t)

	set := BudgetInputSet{
		inputs: []*SweeperInput{{
			Input: mockInput,
			params: Params{
				Budget: budget,
			},
		}},
	}

	// Add many dust UTXOs before one UTXO that can cover the full budget.
	utxos := make([]*lnwallet.Utxo, 0, numDust+1)
	for range numDust {
		utxos = append(utxos, &lnwallet.Utxo{
			AddressType: lnwallet.WitnessPubKey,
			Value:       330,
		})
	}
	utxos = append(utxos, &lnwallet.Utxo{
		AddressType: lnwallet.WitnessPubKey,
		Value:       budget,
	})

	wallet.On(
		"ListUnspentWitnessFromDefaultAccount",
		int32(1), int32(math.MaxInt32),
	).Return(utxos, nil).Once()

	require.NoError(t, set.AddWalletInputs(
		wallet, chainfee.FeePerKwFloor, testMaxFeeRate,
	))
	require.Equal(t, 2, len(set.inputs))
	require.EqualValues(
		t, budget, set.inputs[1].SignDesc().Output.Value,
	)
}

// TestAddWalletInputsSkipsUneconomicalUtxos checks that wallet UTXOs whose
// value cannot cover the fee needed to spend them are not added to the input
// set.
func TestAddWalletInputsSkipsUneconomicalUtxos(t *testing.T) {
	t.Parallel()

	wallet := &MockWallet{}
	defer wallet.AssertExpectations(t)

	const (
		budget  = 5_000_000
		feeRate = chainfee.SatPerKWeight(10_000)
	)

	// Create an input whose required output prevents it from paying its
	// own budget, so the set needs wallet inputs to cover it.
	mockInput := &input.MockInput{}
	mockInput.On("RequiredTxOut").Return(&wire.TxOut{})
	mockInput.On("WitnessType").Return(input.WitnessKeyHash)
	mockInput.On("UnconfParent").Return(nil)
	defer mockInput.AssertExpectations(t)

	sd := &input.SignDescriptor{
		Output: &wire.TxOut{
			Value: budget,
		},
	}
	mockInput.On("SignDesc").Return(sd)

	set := BudgetInputSet{
		inputs: []*SweeperInput{{
			Input: mockInput,
			params: Params{
				Budget:          budget,
				StartingFeeRate: fn.Some(feeRate),
			},
		}},
	}

	// A P2WKH input adds 273 weight units. The set's budget allows a
	// fee rate far above the max fee rate, so economy is judged at the
	// max fee rate, where the input costs 250_000*273/1000 = 68_250
	// satoshis to spend. Create one UTXO that covers its input fee, one
	// UTXO worth exactly its input fee, and many UTXOs that cannot
	// cover it.
	utxos := []*lnwallet.Utxo{
		{
			AddressType: lnwallet.WitnessPubKey,
			Value:       1_000_000,
			OutPoint:    wire.OutPoint{Index: 0},
		},
		{
			AddressType: lnwallet.WitnessPubKey,
			Value:       68_250,
			OutPoint:    wire.OutPoint{Index: 1},
		},
	}
	for i := range 100 {
		utxos = append(utxos, &lnwallet.Utxo{
			AddressType: lnwallet.WitnessPubKey,
			Value:       330,
			OutPoint:    wire.OutPoint{Index: uint32(i + 2)},
		})
	}

	wallet.On(
		"ListUnspentWitnessFromDefaultAccount",
		int32(1), int32(math.MaxInt32),
	).Return(utxos, nil).Once()

	require.NoError(t, set.AddWalletInputs(
		wallet, feeRate, testMaxFeeRate,
	))

	// Only the 1M sat UTXO pays for its own input weight at the max fee
	// rate, so it's the only wallet input added. The UTXO worth exactly
	// its input fee contributes nothing towards the budget and is
	// skipped along with the smaller UTXOs.
	require.Len(t, set.inputs, 2)
	require.EqualValues(
		t, 1_000_000, set.inputs[1].SignDesc().Output.Value,
	)
}

// TestAddWalletInputsMaxWalletInputs checks that when the wallet cannot cover
// the budget, at most maxWalletInputs wallet inputs are added to the set.
func TestAddWalletInputsMaxWalletInputs(t *testing.T) {
	t.Parallel()

	wallet := &MockWallet{}
	defer wallet.AssertExpectations(t)

	const (
		budget    = 6_000_000
		numUtxos  = 1_800
		utxoValue = 3_000

		// maxFeeRate caps the fee rate the set can reach, which keeps
		// the UTXOs economical throughout the selection: a P2WKH input
		// costs 10_000*273/1000 = 2_730 satoshis at that rate.
		maxFeeRate = chainfee.SatPerKWeight(10_000)
	)

	set := BudgetInputSet{
		inputs: []*SweeperInput{{
			Input:  newRequiredOutputInput(t, budget),
			params: Params{Budget: budget},
		}},
	}

	// Create one UTXO that cannot cover the budget on its own, followed
	// by many small UTXOs.
	utxos := newP2WKHUtxos(numUtxos, utxoValue, 1)
	utxos = append(utxos, &lnwallet.Utxo{
		AddressType: lnwallet.WitnessPubKey,
		Value:       1_000_000,
	})

	wallet.On(
		"ListUnspentWitnessFromDefaultAccount",
		int32(1), int32(math.MaxInt32),
	).Return(utxos, nil).Once()

	require.NoError(t, set.AddWalletInputs(
		wallet, chainfee.FeePerKwFloor, maxFeeRate,
	))

	// The large UTXO is selected first, and selection stops at the max
	// number of wallet inputs.
	require.Len(t, set.inputs, 1+maxWalletInputs)
	require.EqualValues(
		t, 1_000_000, set.inputs[1].SignDesc().Output.Value,
	)
}

// TestAddWalletInputsWeightLimit checks that wallet inputs are only added
// while the sweep transaction stays below the standardness weight limit.
func TestAddWalletInputsWeightLimit(t *testing.T) {
	t.Parallel()

	wallet := &MockWallet{}
	defer wallet.AssertExpectations(t)

	const (
		numSetInputs = 1_250
		inputBudget  = 1_000
		utxoValue    = 3_000
		maxFeeRate   = chainfee.SatPerKWeight(10_000)
	)

	// Create a heavy set whose own inputs leave room for fewer than
	// maxWalletInputs wallet inputs below the weight limit.
	mockInput := newRequiredOutputInput(t, inputBudget)

	set := BudgetInputSet{}
	for range numSetInputs {
		set.inputs = append(set.inputs, &SweeperInput{
			Input:  mockInput,
			params: Params{Budget: inputBudget},
		})
	}

	wallet.On(
		"ListUnspentWitnessFromDefaultAccount",
		int32(1), int32(math.MaxInt32),
	).Return(newP2WKHUtxos(maxWalletInputs, utxoValue, 0), nil).Once()

	require.NoError(t, set.AddWalletInputs(
		wallet, chainfee.FeePerKwFloor, maxFeeRate,
	))

	// Some wallet inputs are added, but the weight limit stops the
	// selection before the max number of wallet inputs is reached.
	numWallet := len(set.inputs) - numSetInputs
	require.Positive(t, numWallet)
	require.Less(t, numWallet, maxWalletInputs)

	// Recompute the weight of the final input set and assert it stays
	// within the standardness weight limit.
	weightEstimate := newWeightEstimator(chainfee.FeePerKwFloor, 0)
	for _, inp := range set.inputs {
		require.NoError(t, weightEstimate.add(inp.Input))

		if txOut := inp.RequiredTxOut(); txOut != nil {
			weightEstimate.addOutput(txOut)
		}
	}
	weightEstimate.addP2TROutput()

	require.LessOrEqual(t, weightEstimate.weight(), maxStandardTxWeight)
}

// TestAddWalletInputsSkipsDustAtMaxFeeRate checks that small wallet UTXOs
// are not added to the set when they cannot pay for their own input weight
// at the maximum fee rate the set can reach, even though they could pay it
// at the relay fee floor.
func TestAddWalletInputsSkipsDustAtMaxFeeRate(t *testing.T) {
	t.Parallel()

	wallet := &MockWallet{}
	defer wallet.AssertExpectations(t)

	const (
		budget    = 5_000_000
		numUtxos  = 1_800
		utxoValue = 330
	)

	// Create an input whose required output prevents it from paying its
	// own budget, so the set needs wallet inputs to cover it. No starting
	// fee rate is set, so the relay fee floor is the starting rate.
	mockInput := &input.MockInput{}
	mockInput.On("RequiredTxOut").Return(&wire.TxOut{})
	mockInput.On("WitnessType").Return(input.WitnessKeyHash)
	mockInput.On("UnconfParent").Return(nil)
	defer mockInput.AssertExpectations(t)

	sd := &input.SignDescriptor{
		Output: &wire.TxOut{
			Value: budget,
		},
	}
	mockInput.On("SignDesc").Return(sd)

	set := BudgetInputSet{
		inputs: []*SweeperInput{{
			Input: mockInput,
			params: Params{
				Budget: budget,
			},
		}},
	}

	// Create one UTXO that pays for its input weight at any fee rate,
	// followed by many small UTXOs that can only pay for their input
	// weight at low fee rates.
	utxos := []*lnwallet.Utxo{
		{
			AddressType: lnwallet.WitnessPubKey,
			Value:       1_000_000,
			OutPoint:    wire.OutPoint{Index: 0},
		},
	}
	for i := range numUtxos {
		utxos = append(utxos, &lnwallet.Utxo{
			AddressType: lnwallet.WitnessPubKey,
			Value:       utxoValue,
			OutPoint:    wire.OutPoint{Index: uint32(i + 1)},
		})
	}

	wallet.On(
		"ListUnspentWitnessFromDefaultAccount",
		int32(1), int32(math.MaxInt32),
	).Return(utxos, nil).Once()

	require.NoError(t, set.AddWalletInputs(
		wallet, chainfee.FeePerKwFloor, testMaxFeeRate,
	))

	// The budget allows the set to reach the max fee rate, where a P2WKH
	// input costs 250_000*273/1000 = 68_250 satoshis. Only the large UTXO
	// pays for its own input weight at that rate, so it's the only wallet
	// input added and the set sweeps underfunded.
	require.Len(t, set.inputs, 2)
	require.EqualValues(
		t, 1_000_000, set.inputs[1].SignDesc().Output.Value,
	)

	// The resulting transaction stays far below the standardness weight
	// limit.
	weightEstimate := newWeightEstimator(chainfee.FeePerKwFloor, 0)
	for _, inp := range set.inputs {
		require.NoError(t, weightEstimate.add(inp.Input))

		if txOut := inp.RequiredTxOut(); txOut != nil {
			weightEstimate.addOutput(txOut)
		}
	}
	weightEstimate.addP2TROutput()

	require.Less(t, weightEstimate.weight(), lntypes.WeightUnit(10_000))
}

// TestAddWalletInputsSmallUtxosOnly checks that when no wallet UTXO can pay
// for its own input weight at the set's max fee rate, and the set has no other
// input that can pay fees, UTXOs that raise the fee rate the set can reach are
// still added so the sweep can be published.
func TestAddWalletInputsSmallUtxosOnly(t *testing.T) {
	t.Parallel()

	wallet := &MockWallet{}
	defer wallet.AssertExpectations(t)

	const (
		budget    = 500_000
		numUtxos  = 20
		utxoValue = 50_000
	)

	// Create an input whose required output prevents it from paying its
	// own budget, so it cannot pay fees itself.
	mockInput := &input.MockInput{}
	mockInput.On("RequiredTxOut").Return(&wire.TxOut{})
	mockInput.On("WitnessType").Return(input.WitnessKeyHash)
	mockInput.On("UnconfParent").Return(nil)
	defer mockInput.AssertExpectations(t)

	sd := &input.SignDescriptor{
		Output: &wire.TxOut{
			Value: budget,
		},
	}
	mockInput.On("SignDesc").Return(sd).Maybe()

	set := BudgetInputSet{
		inputs: []*SweeperInput{{
			Input: mockInput,
			params: Params{
				Budget: budget,
			},
		}},
	}

	// At the max fee rate a P2WKH input costs 68_250 satoshis, so none of
	// these UTXOs is economical there, while each of them is at the
	// starting fee rate.
	utxos := make([]*lnwallet.Utxo, 0, numUtxos)
	for i := range numUtxos {
		utxos = append(utxos, &lnwallet.Utxo{
			AddressType: lnwallet.WitnessPubKey,
			Value:       utxoValue,
			OutPoint:    wire.OutPoint{Index: uint32(i)},
		})
	}

	wallet.On(
		"ListUnspentWitnessFromDefaultAccount",
		int32(1), int32(math.MaxInt32),
	).Return(utxos, nil).Once()

	require.NoError(t, set.AddWalletInputs(
		wallet, chainfee.FeePerKwFloor, testMaxFeeRate,
	))

	// Each UTXO raises the fee rate the set can reach, so wallet inputs
	// are added until the budget is covered: the budget of 500_000 needs
	// ten UTXOs of 50_000.
	require.Len(t, set.inputs, 1+budget/utxoValue)
	require.True(t, set.hasNormalInput())
	require.False(t, set.NeedWalletInput())
}

// TestAddWalletInputsSuccess checks that when there are enough wallet utxos,
// they are added to the input set.
func TestAddWalletInputsSuccess(t *testing.T) {
	t.Parallel()

	wallet := &MockWallet{}
	defer wallet.AssertExpectations(t)

	// Specify the min and max confs used in
	// ListUnspentWitnessFromDefaultAccount.
	min, max := int32(1), int32(math.MaxInt32)

	// Assume the desired budget is 10k satoshis.
	const budget = 10_000

	// Create a mock input that has required outputs.
	mockInput := &input.MockInput{}
	mockInput.On("RequiredTxOut").Return(&wire.TxOut{})
	defer mockInput.AssertExpectations(t)

	// Create a pending input that requires 10k satoshis.
	deadline := int32(1000)
	pi := &SweeperInput{
		Input: mockInput,
		params: Params{
			Budget:         budget,
			DeadlineHeight: fn.Some(deadline),
		},
	}

	// Mock methods used in loggings.
	//
	// NOTE: these methods are not functional as they are only used for
	// loggings in debug or trace mode so we use arbitrary values.
	mockInput.On("OutPoint").Return(wire.OutPoint{Hash: chainhash.Hash{1}})
	mockInput.On("WitnessType").Return(input.CommitmentAnchor)

	// Mock the method used when checking for CPFP requirements.
	mockInput.On("UnconfParent").Return(nil)

	// Create a wallet utxo that cannot cover the budget.
	utxo := &lnwallet.Utxo{
		AddressType: lnwallet.WitnessPubKey,
		Value:       budget - 1,
	}

	// Mock the wallet to return the two utxos which can cover the budget.
	wallet.On("ListUnspentWitnessFromDefaultAccount",
		min, max).Return([]*lnwallet.Utxo{utxo, utxo}, nil).Once()

	// Initialize an input set with the pending input.
	set, err := NewBudgetInputSet(
		[]SweeperInput{*pi}, deadline, fn.None[AuxSweeper](),
	)
	require.NoError(t, err)

	// Add wallet inputs to the input set, which should give us an error as
	// the wallet cannot cover the budget.
	err = set.AddWalletInputs(
		wallet, chainfee.FeePerKwFloor, testMaxFeeRate,
	)
	require.NoError(t, err)

	// Check that the budget set is updated.
	require.Len(t, set.inputs, 3)

	// The first input is the pending input.
	require.Equal(t, pi, set.inputs[0])

	// The second and third inputs are wallet inputs that have
	// DeadlineHeight set.
	input2Deadline := set.inputs[1].params.DeadlineHeight
	require.Equal(t, deadline, input2Deadline.UnsafeFromSome())
	input3Deadline := set.inputs[2].params.DeadlineHeight
	require.Equal(t, deadline, input3Deadline.UnsafeFromSome())

	// Finally, check the interface methods.
	require.EqualValues(t, budget, set.Budget())
	require.Equal(t, deadline, set.DeadlineHeight())
	// Weak check, a strong check is to open the slice and check each item.
	require.Len(t, set.inputs, 3)
}

// newRequiredOutputInput returns a mock input with a required output, such as
// a second-level HTLC input, which cannot pay fees itself.
func newRequiredOutputInput(t *testing.T,
	value btcutil.Amount) *input.MockInput {

	mockInput := &input.MockInput{}
	t.Cleanup(func() { mockInput.AssertExpectations(t) })

	mockInput.On("RequiredTxOut").Return(&wire.TxOut{})
	mockInput.On("WitnessType").Return(input.WitnessKeyHash)
	mockInput.On("UnconfParent").Return(nil)
	mockInput.On("SignDesc").Return(&input.SignDescriptor{
		Output: &wire.TxOut{Value: int64(value)},
	}).Maybe()

	return mockInput
}

// newP2WKHUtxos returns num P2WKH wallet UTXOs of the given value, with output
// indexes starting at firstIndex.
func newP2WKHUtxos(num int, value btcutil.Amount,
	firstIndex uint32) []*lnwallet.Utxo {

	utxos := make([]*lnwallet.Utxo, 0, num)
	for i := range num {
		utxos = append(utxos, &lnwallet.Utxo{
			AddressType: lnwallet.WitnessPubKey,
			Value:       value,
			OutPoint: wire.OutPoint{
				Index: firstIndex + uint32(i),
			},
		})
	}

	return utxos
}

// TestAddWalletInputsAnchorSmallUtxos checks that an anchor CPFP set, whose
// anchor can pay fees but is far too small to cover its budget, is funded by
// wallet UTXOs that cannot pay for their own input weight at the set's max fee
// rate.
func TestAddWalletInputsAnchorSmallUtxos(t *testing.T) {
	t.Parallel()

	wallet := &MockWallet{}
	defer wallet.AssertExpectations(t)

	const (
		budget    = 500_000
		numUtxos  = 20
		utxoValue = 50_000
	)

	// Create an anchor input. It has no required output, but its value
	// is far below its budget, which must be borrowed from the wallet.
	anchor := &input.MockInput{}
	defer anchor.AssertExpectations(t)

	anchor.On("RequiredTxOut").Return(nil)
	anchor.On("WitnessType").Return(input.CommitmentAnchor)
	anchor.On("UnconfParent").Return(nil)
	anchor.On("SignDesc").Return(&input.SignDescriptor{
		Output: &wire.TxOut{Value: 330},
	})

	set := BudgetInputSet{
		inputs: []*SweeperInput{{
			Input:  anchor,
			params: Params{Budget: budget},
		}},
	}

	// At the max fee rate a P2WKH input costs 68_250 satoshis, so none of
	// these UTXOs pays for itself there.
	wallet.On(
		"ListUnspentWitnessFromDefaultAccount",
		int32(1), int32(math.MaxInt32),
	).Return(newP2WKHUtxos(numUtxos, utxoValue, 0), nil).Once()

	require.NoError(t, set.AddWalletInputs(
		wallet, chainfee.FeePerKwFloor, testMaxFeeRate,
	))

	// The anchor plus ten UTXOs of 50_000 cover the budget of 500_000.
	require.Len(t, set.inputs, 1+budget/utxoValue)
	require.False(t, set.NeedWalletInput())
}

// TestAddWalletInputsAnchorHeavyParent checks that an anchor CPFP set whose
// unconfirmed parent dominates the package weight keeps adding wallet UTXOs
// that raise the package fee rate, even after a large UTXO has made the
// child's own fee rate higher than those UTXOs can pay for. This must hold
// whether the parent pays below or above the starting fee rate, as fee bumps
// can raise the child's fee rate well above what the parent pays. A parent
// paying more than the child can reach is mined on its own, so the child is
// then judged by its own fee rate.
func TestAddWalletInputsAnchorHeavyParent(t *testing.T) {
	t.Parallel()

	const (
		budget       = 500_000
		numSmall     = 20
		largeValue   = 100_000
		parentWeight = 20_000
	)

	testCases := []struct {
		name      string
		parentFee btcutil.Amount

		// smallValue is the value of each of the small UTXOs.
		smallValue btcutil.Amount

		// numInputs is the expected number of inputs in the set,
		// including the anchor.
		numInputs int
	}{
		{
			// The parent pays 100 sat/kw, below the starting fee
			// rate.
			name:       "parent below starting fee rate",
			parentFee:  2_000,
			smallValue: 15_000,
			numInputs:  1 + 1 + numSmall,
		},
		{
			// The parent pays 1,000 sat/kw, above the starting fee
			// rate but far below the max fee rate.
			name:       "parent above starting fee rate",
			parentFee:  20_000,
			smallValue: 15_000,
			numInputs:  1 + 1 + numSmall,
		},
		{
			// The parent pays 200,000 sat/kw, above the child's
			// reachable fee rate, so the child is judged by its
			// own fee rate. The small UTXOs are below the package's
			// fee rate but raise the child's, so they're added
			// until the ten of them cover the budget.
			name:       "parent above child's reachable fee rate",
			parentFee:  4_000_000,
			smallValue: 40_000,
			numInputs:  1 + 1 + 10,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			wallet := &MockWallet{}
			defer wallet.AssertExpectations(t)

			anchor := &input.MockInput{}
			defer anchor.AssertExpectations(t)

			anchor.On("RequiredTxOut").Return(nil)
			anchor.On("WitnessType").Return(
				input.CommitmentAnchor,
			)
			anchor.On("OutPoint").Return(wire.OutPoint{Index: 7})
			anchor.On("UnconfParent").Return(&input.TxInfo{
				Fee:    tc.parentFee,
				Weight: parentWeight,
			})
			anchor.On("SignDesc").Return(&input.SignDescriptor{
				Output: &wire.TxOut{Value: 330},
			})

			set := BudgetInputSet{
				inputs: []*SweeperInput{{
					Input:  anchor,
					params: Params{Budget: budget},
				}},
			}

			// After the large UTXO is added, the child's own
			// reachable fee rate is far above the value per weight
			// unit of the small UTXOs, while the package's
			// reachable fee rate is far below it.
			utxos := newP2WKHUtxos(
				numSmall, tc.smallValue, 1,
			)
			utxos = append(utxos, &lnwallet.Utxo{
				AddressType: lnwallet.WitnessPubKey,
				Value:       largeValue,
			})

			wallet.On(
				"ListUnspentWitnessFromDefaultAccount",
				int32(1), int32(math.MaxInt32),
			).Return(utxos, nil).Once()

			require.NoError(t, set.AddWalletInputs(
				wallet, chainfee.FeePerKwFloor, testMaxFeeRate,
			))

			// The large UTXO is always added first, followed by
			// small UTXOs until the budget is covered or the
			// wallet runs out.
			require.Len(t, set.inputs, tc.numInputs)
			require.EqualValues(
				t, largeValue,
				set.inputs[1].SignDesc().Output.Value,
			)
		})
	}
}

// TestAddWalletInputsTopUpAfterLargeUtxo checks that when the largest wallet
// UTXO cannot cover the budget, smaller UTXOs that raise the fee rate the set
// can reach are added on top of it.
func TestAddWalletInputsTopUpAfterLargeUtxo(t *testing.T) {
	t.Parallel()

	wallet := &MockWallet{}
	defer wallet.AssertExpectations(t)

	const budget = 500_000

	set := BudgetInputSet{
		inputs: []*SweeperInput{{
			Input:  newRequiredOutputInput(t, budget),
			params: Params{Budget: budget},
		}},
	}

	// The 100_000 sat UTXO pays for itself at the max fee rate, while the
	// 50_000 sat UTXOs don't.
	utxos := newP2WKHUtxos(20, 50_000, 1)
	utxos = append(utxos, &lnwallet.Utxo{
		AddressType: lnwallet.WitnessPubKey,
		Value:       100_000,
	})

	wallet.On(
		"ListUnspentWitnessFromDefaultAccount",
		int32(1), int32(math.MaxInt32),
	).Return(utxos, nil).Once()

	require.NoError(t, set.AddWalletInputs(
		wallet, chainfee.FeePerKwFloor, testMaxFeeRate,
	))

	// The large UTXO is added first, then eight UTXOs of 50_000 top up
	// the budget.
	require.Len(t, set.inputs, 1+1+8)
	require.EqualValues(
		t, 100_000, set.inputs[1].SignDesc().Output.Value,
	)
	require.False(t, set.NeedWalletInput())
}

// TestAddWalletInputsCapsStartingFeeRate checks that the starting fee rate
// used to judge wallet inputs is capped at the fee rate allowed by the set's
// budget, matching the linear fee function.
func TestAddWalletInputsCapsStartingFeeRate(t *testing.T) {
	t.Parallel()

	wallet := &MockWallet{}
	defer wallet.AssertExpectations(t)

	const (
		budget       = 1_000
		utxoValue    = 2_000
		startFeeRate = chainfee.SatPerKWeight(10_000)
	)

	set := BudgetInputSet{
		inputs: []*SweeperInput{{
			Input:  newRequiredOutputInput(t, budget),
			params: Params{Budget: budget},
		}},
	}

	// The P2WKH UTXO's density is below startFeeRate, but above the lower
	// fee-rate ceiling imposed by the set's budget. The fee function caps
	// its starting rate at that ceiling, so the UTXO is economical and must
	// be added.
	wallet.On(
		"ListUnspentWitnessFromDefaultAccount",
		int32(1), int32(math.MaxInt32),
	).Return(newP2WKHUtxos(1, utxoValue, 0), nil).Once()

	require.NoError(t, set.AddWalletInputs(
		wallet, startFeeRate, testMaxFeeRate,
	))
	require.Len(t, set.inputs, 2)
	require.False(t, set.NeedWalletInput())
}

// TestAddWalletInputsSkipsDustAtStartingFeeRate checks that wallet UTXOs that
// cannot pay for their own input weight at the starting fee rate are never
// added, even when the set has no other input that can pay fees.
func TestAddWalletInputsSkipsDustAtStartingFeeRate(t *testing.T) {
	t.Parallel()

	const (
		budget  = 500_000
		numDust = 100
	)

	newSet := func() *BudgetInputSet {
		return &BudgetInputSet{
			inputs: []*SweeperInput{{
				Input:  newRequiredOutputInput(t, budget),
				params: Params{Budget: budget},
			}},
		}
	}

	// A P2WKH input of 330 satoshis pays for itself up to about 1_208
	// sat/kw.
	utxos := newP2WKHUtxos(numDust, 330, 0)

	// At a starting fee rate of 5_000 sat/kw, none of the dust is added,
	// and as the set has no input that can pay fees, it can't be swept.
	wallet := &MockWallet{}
	defer wallet.AssertExpectations(t)

	wallet.On(
		"ListUnspentWitnessFromDefaultAccount",
		int32(1), int32(math.MaxInt32),
	).Return(utxos, nil).Once()

	set := newSet()
	err := set.AddWalletInputs(wallet, 5_000, testMaxFeeRate)
	require.ErrorIs(t, err, ErrNotEnoughInputs)
	require.Len(t, set.inputs, 1)

	// At the relay fee floor, the dust pays for itself and is added.
	wallet.On(
		"ListUnspentWitnessFromDefaultAccount",
		int32(1), int32(math.MaxInt32),
	).Return(utxos, nil).Once()

	set = newSet()
	require.NoError(t, set.AddWalletInputs(
		wallet, chainfee.FeePerKwFloor, testMaxFeeRate,
	))
	require.Len(t, set.inputs, 1+numDust)
}

// TestAddWalletInputsValueDensityOrder checks that wallet UTXOs are
// considered in order of value per weight unit, so a smaller UTXO of a
// lighter address type is preferred over a larger, heavier one when it pays
// more per weight unit.
func TestAddWalletInputsValueDensityOrder(t *testing.T) {
	t.Parallel()

	wallet := &MockWallet{}
	defer wallet.AssertExpectations(t)

	const budget = 9_000

	set := BudgetInputSet{
		inputs: []*SweeperInput{{
			Input:  newRequiredOutputInput(t, budget),
			params: Params{Budget: budget},
		}},
	}

	// A P2WKH input adds 273 weight units and a P2TR key spend input
	// fewer, so the 9_500 sat P2TR UTXO pays more per weight unit than
	// the 10_000 sat P2WKH UTXO.
	utxos := []*lnwallet.Utxo{
		{
			AddressType: lnwallet.WitnessPubKey,
			Value:       10_000,
			OutPoint:    wire.OutPoint{Index: 0},
		},
		{
			AddressType: lnwallet.TaprootPubkey,
			Value:       9_500,
			OutPoint:    wire.OutPoint{Index: 1},
		},
	}

	wallet.On(
		"ListUnspentWitnessFromDefaultAccount",
		int32(1), int32(math.MaxInt32),
	).Return(utxos, nil).Once()

	require.NoError(t, set.AddWalletInputs(
		wallet, chainfee.FeePerKwFloor, testMaxFeeRate,
	))

	// The P2TR UTXO alone covers the budget.
	require.Len(t, set.inputs, 2)
	require.EqualValues(t, 9_500, set.inputs[1].SignDesc().Output.Value)
}
