# PR draft: the interval router

Working notes for the pull request that takes this branch upstream. Not part of
the shipped documentation, and to be deleted before the branch merges. The
reader-facing explanation lives in `docs/interval_routing.md`.

## Title

`routing: add an experimental interval router behind a config flag`

## Description

In this PR, we add a second way for lnd to choose a route, selectable with
`routerrpc.router=interval` and off by default.

The stock router asks whether the graph can carry an amount that was fixed
before path finding began, and halves the amount when the answer is no. This one
asks what the network will accept and picks the amount and the route together.
Everything else follows from that.

In place of mission control's penalty per node pair, decaying on a half life, it
keeps a liquidity interval per directed channel: the largest amount it has
watched pass, the smallest it has watched fail, and an estimate in between.
There is no clock anywhere in the model. Every observation writes both
directions, because liquidity not on one side of a funding output is on the
other, which is an inference mission control does not make. A failure records
an amount rather than a verdict, so a channel that just refused 400,000
satoshis is still the obvious way to send 40,000, with no penalty to wait out.

Splitting is planned rather than reactive. For one route request the session
builds a ladder of candidate shard sizes, finds a route for each, and takes the
best pairing of the two. The ladder includes sizes derived from amounts this
payment has already proven do not fit, which is the part that makes it more than
a reordering of the halving loop.

The payment lifecycle is untouched. It still asks for one route at a time and
dispatches one HTLC at a time; the shard size rides back on the route, since
`registerAttempt` already reads `ReceiverAmt()`. Mission control keeps running
alongside, keeps its history and its RPCs, and still decides whether a failure
is terminal. Only the choice of route changes.

### What is in the branch

In dependency order, which is also the order to review:

1. A seam letting a payment session hear the outcomes of the attempts it handed
   out. The lifecycle reported to mission control and nowhere else; a session
   with beliefs of its own needs the same stream. Optional, so the stock session
   does not implement it and nothing changes with the flag off.
2. The belief store: the interval, its update rules, and a bimodal prior whose
   scale is a fraction of capacity rather than a fixed number of millisatoshis,
   which is what lets one set of constants work across channel sizes.
3. A label setting search that keeps a bounded set of Pareto-incomparable labels
   per node, because a route that is cheaper but carries a larger amount is not
   comparable to one that is dearer and carries less.
4. The session: the shard ladder, the per-payment state, and the fallback for
   payment shapes the router does not serve.
5. Config wiring, sample conf, and the release note.
6. Persistence to the native SQL store, with a new `liquidity_intervals` table.
7. Pricing a shard against HTLCs we already hold on interior channels.
8. A budget derived exchange rate between fees and reliability.

### Evidence

The design was arrived at by evolutionary search against an in-process payment
simulator, and then validated against lnd's production stack on held-out
scenarios. What the branch rests on:

- **In-simulation, 14 of 14 tiers CI-solid over stock lnd**, across clean,
  degraded, split, atomic and mainnet-derived scenario families.
- **The margins re-pin on files nobody had seen.** Regenerating the corpora
  fresh, thirty files per family, the leads over stock lnd come back larger than
  the sealed tiers had shown: the hard family lands between +0.16 and +0.26 of
  objective, every one at p below 2e-3, and mainnet at +0.096. The collapse that
  degraded attribution induces in stock lnd reproduces on the unseen files too,
  which is the part that was most worth checking, since it is the finding the
  whole design leans on.
- **Production-default fee limits.** The margins hold when payments carry the
  fee limit `lnrpc.CalculateFeeLimit` gives them by default, which is the limit
  every RPC payment actually carries.
- **External-graph parity.** On a channel graph generated outside this work, the
  router holds parity with the best routers the search produced, which is the
  closest thing available to an out-of-sample check on a topology nobody here
  chose.
- **An integration test** over a three hop network with the flag on, covering a
  payment that settles, one that fails on liquidity at the middle hop, and a
  smaller one that settles immediately afterwards with nothing reset, which is
  the behaviour the whole design is for.

### What this is not

Stated plainly, because the evidence above is easy to over-read.

- **Everything above was measured in simulation.** No number here comes from
  mainnet. The simulator's liquidity is drawn from a generator, and while the
  mainnet-derived tiers use real topology and real policies, their balances are
  synthetic. That is the single largest caveat on the whole branch.
- **The scenarios are ones we chose.** Thirteen paired tiers moving the
  liquidity family, the amount family and the graph itself did not change the
  ordering, which is evidence against overfitting rather than proof of its
  absence.
- **One interaction was found and explained, and the fix rests on the mechanism
  rather than on a measured gain.** A tier mixing unreadable errors with shifted
  blame behaved worse than either ingredient alone. The cause is the
  quarantine's trust boundary: a failure that names the wrong hop makes the
  router write a lower bound on the channel that actually refused, and the
  quarantine was reading that bound as proof of innocence, letting the culprit
  out of every suspicion and concentrating the blame on its neighbours. Two
  things establish that. Ablating the ingredients separates them cleanly, since
  neither unreadable errors nor shifted blame does this alone. And ground truth
  counters name the victims: on the mixed tier 9.6% of promoted bounds landed on
  channels that had never failed, against 0.0% when only unreadable errors were
  present.

  What does not survive is the size of it. On thirty freshly generated files of
  that family the objective-level effect is indistinguishable from zero, in both
  directions, and the ten files it was first seen on could not have pinned an
  effect that small against a per-file spread reaching 0.29. So we keep the fix
  on the grounds that it stops the router accepting evidence that misattribution
  manufactures, and we do not claim it buys anything measurable. Its cost is
  likewise not measurable at thirty files, which is the other half of why it
  stays.
- **The quarantine mechanism measured as a null** on the tiers built to reward
  it. It is behind `DisableQuarantine` and can be switched off, or dropped by
  reverting its commits, without touching anything else.
- **The beliefs are simulator-shaped in one specific way.** Several constants in
  the probability model were selected by a search against a generator whose
  liquidity distribution the constants then came to fit. The mechanism is what
  transfers; the constants are the part to be suspicious of.

### Known limitations

- **One deficit against the evolved routers survives the wider corpus.** On
  degraded mainnet the router sits 0.021 of objective below the best of them,
  with the interval spanning -0.042 to +0.001 at thirty files: the direction has
  held everywhere it has been measured, and it has never been separated from
  zero. What the other router has there, and this one does not, is that
  degrading attribution costs it no success at all, 0.557 either way. We have
  not reproduced that invariance and we do not claim it.
- Payments to blinded paths are served by the stock session. Inside a blinded
  path there is no channel to key a belief on, and an error from inside one
  names nothing further in. The fallback is transparent: the session handed out
  is the one the stock source would have produced.
- A resumed payment's in-flight HTLCs are not counted as holds, because the
  router did not choose their routes and cannot say which channels they sit on.
- An ambiguous failure is recorded against the node pair rather than the
  channel, since non-strict forwarding means the evidence cannot name one.
- Searching costs more than a single Dijkstra run, which is the main reason the
  router is off by default.
- Persistence needs the native SQL backend. Elsewhere the router starts cold.

### Reviewing this

The flag is off by default, and with it off none of the new code is constructed:
the server builds the same session source it always did, and the lifecycle seam
is a type assertion the stock session does not satisfy. The commits build and
pass tests individually.

`docs/interval_routing.md` explains the algorithm for someone who has not seen
this line of work, and is the place to start.

## Release note

Already in `docs/release-notes/release-notes-0.22.0.md` under Functional
Enhancements and Database. The pull request number needs filling in once it
exists; it is written as `/pull/0` in three places.

## Before opening

- [ ] Fill in the PR number in the release notes.
- [ ] Delete this file.
- [ ] Rebase onto current master. The last audit found the drift mechanical:
      one shared file, `itest/list_on_test.go`, with the hunks hundreds of lines
      apart.
- [ ] Decide keep or drop on the quarantine.
- [ ] Re-run the itest and the full unit battery under both database tags.
