# The Interval Router

What is the largest amount this route can still carry?

That question is the whole of the difference between the interval router and
the one lnd has always shipped. The stock router asks whether the graph can
carry an amount that was fixed before path finding began, and when the answer
is no, it halves the amount and asks again. The interval router asks what the
network will accept, and picks the amount and the route together.

This is written for an lnd contributor seeing the algorithm for the first
time. It is off by default.

## What the router remembers

Mission control remembers a penalty. When an attempt fails at some node pair,
it records that pair as a bad bet and lets the record fade on a half life, so
that a channel which was empty an hour ago becomes worth trying again today.

The interval router remembers an amount range instead. For each direction of
each channel it keeps three numbers:

- `LowerOK`, the largest amount it has watched pass. Anything at or below this
  is treated as near certain.
- `UpperFail`, the smallest amount it has watched fail. Anything at or above
  this is treated as impossible.
- `Estimate`, its best guess at the balance, somewhere between the two.

Alongside them it keeps a confidence, which rises as evidence accumulates, and
a classification: whether the channel looks nearly empty in this direction,
nearly full, or neither.

There is no clock anywhere in the model. A bound moves when evidence arrives
and never because time has passed. That is the largest departure from mission
control, and the one that takes the most care to get right, since a belief with
no expiry is a belief that has to be correct.

### Every observation writes both directions

A payment attempt teaches the router three kinds of thing, and each of them
writes the channel it names and also the same channel in reverse.

A **failure** at some hop drops that direction's `UpperFail` to the amount that
was refused. It also raises the reverse direction's `LowerOK`, because
liquidity that is not on this side of the funding output is on the other side.
A channel that cannot send you 400,000 satoshis is a channel that can probably
send 400,000 satoshis back. Mission control makes no such inference; its
two directions of a pair are wholly independent records.

A **probe** is what the router learns about the hops it did not fail at. If an
attempt fails four hops out, the first three hops forwarded, which proves they
could carry what they were handed. That raises their `LowerOK` and lowers the
reverse `UpperFail`.

A **settlement** is different in kind from both, because the money actually
moved. The forward interval slides down by the amount that left and the reverse
interval slides up by the same, so the router's picture of the channel tracks
the payment it just made rather than merely narrowing around it.

### What it believes with no evidence at all

Before any of that, the router needs an opinion about a channel it has never
touched. It assumes liquidity is bimodal: a channel is usually sitting near one
end of its range rather than politely balanced in the middle. So a small amount
is nearly certain to pass, an amount near the whole capacity is nearly certain
to fail, and the transition between the two is narrow.

The width of that transition is a fraction of capacity, not a number of
satoshis. lnd's bimodal estimator takes a scale in millisatoshis, defaulting to
300,000 satoshis, which is 30% of a 1,000,000 satoshi channel and under 2% of a
16,000,000 satoshi one. Expressing the same shape as a percentage of capacity
is what lets one set of constants work on channels that differ in size by
orders of magnitude.

## How it finds a route

The search runs backwards from the destination, the same as `findPath`, and it
reuses the machinery that makes that walk correct: the edge unifier that picks
a policy per node pair, the bandwidth hints that speak for our own channels,
the fee and time lock limits, the onion payload budget, and the feature
validation of every node on the way.

Two things differ.

**The cost of a hop is additive.** The stock router minimizes fee plus a time
lock penalty, divided through by the probability of the route. The interval
router minimizes the negative logarithm of that probability, plus terms for
fee, for depth, and for how much of a channel the payment would fill.
Logarithms turn the product of hop probabilities into a sum, which is what
makes the search below tractable, and it is far gentler on a route the model is
merely unsure about than dividing by a small number is.

**A node keeps several answers, not one.** Dijkstra keeps the single best
distance per node. This search keeps a bounded set of labels that no other
label beats on all three of cost, amount, and hop count at once. It needs to,
because the search runs backwards and fees accumulate as it goes. A route that
is cheaper but carries a larger amount is not comparable to one that is dearer
and carries less, since the larger amount may be refused further upstream. A
single distance per node cannot express that, and the amounts the shard ladder
wants to compare are exactly the ones where it matters.

## How it splits a payment

lnd splits a multi-path payment reactively. `paymentSession.RequestRoute` asks
for the whole remaining amount, and when path finding comes back empty it
halves the amount and tries again, stopping at the minimum shard size or the
part limit. Every split is a response to a failure, and every shard is a
power-of-two fraction.

The interval router plans the split. For one call it builds a ladder of
candidate amounts, finds a route for each, and keeps the pairing of amount and
route with the best score. The ladder draws on four sources:

1. the whole remaining amount, and the smallest shard that could still finish
   the payment inside the parts left;
2. the amounts this payment has already proven do not fit, divided down until
   they do;
3. even divisions of the remaining amount;
4. the halving chain, and small multiples of the smallest usable shard.

Source 2 is the one that makes this more than a reordering of lnd's loop. A
failure at 400,000 satoshis, for instance, immediately puts 199,999 and 99,999
into play, and the halving chain would reach those amounts only by accident.
Because every rung costs a full search, the ladder is capped, and the sources
are enumerated in the order above so that the cap keeps the informative rungs.

Scoring a rung trades the risk of its route against how much of the payment it
would carry, with an appetite for large shards that responds to how the payment
is going: bolder once a part has settled and the payment is committed, more
cautious after several failures.

The payment lifecycle is untouched by any of this. It still asks for one route
at a time and dispatches one HTLC, or hash time locked contract, at a time. The
shard size simply rides back on the route, since `registerAttempt` already
reads `ReceiverAmt()` to decide whether a shard is the last one.

## Living alongside mission control

Turning the interval router on does not turn mission control off. Mission
control keeps running, keeps its history, keeps answering
`QueryProbability` and the rest of its remote procedure calls, and keeps
deciding whether a given failure is terminal for the payment. Only the choice
of route changes.

Every attempt outcome therefore reaches two places. The payment lifecycle
reports it to mission control exactly as before, and then offers it to the
payment session through a small optional interface, `PaymentResultReporter`.
The stock session does not implement that interface, so with the flag off the
type assertion fails and nothing changes.

The interval beliefs live in an `IntervalStore`, one per node and shared by
every payment, so what one payment learns is there for the next. On
a node running the native SQL backend the store also writes its beliefs down
and reads them back at startup. Elsewhere it is memory only and the router
starts cold after a restart.

## Turning it on

```
[routerrpc]
routerrpc.router=interval
```

The other value is `default`, the stock stack, and it is what a node that says
nothing gets. With the flag off, none of the code described here is even
constructed.

## Limitations

**Payments to blinded paths fall back to the stock session.** Inside a blinded
path there is no channel for the model to key a belief on: the hops are opaque,
the intermediate amounts and expiries are deliberately zero, and an error from
inside the path arrives as `invalid_onion_blinding` from the introduction node,
which names nothing further in. Intervals on the visible prefix up to the
introduction node would work, since those hops are ordinary channels and a
failure past them proves they forwarded. Getting there also means teaching the
search about the dummy hop appended to blinded routes and about targeting the
nothing-up-my-sleeve (NUMS) key rather than the destination, so for now these
payments are handed to the router that already gets them right.

**A restored bound is softer than a fresh one.** This model has no way back
from a wrong `UpperFail`: an amount the model calls impossible is never
attempted, and an attempt is the only thing that could correct the bound. That
is the right trade while the evidence is fresh and ours. It is a trapdoor for a
bound loaded from disk, because the network that bound describes has had every
restart and every rebalance since to move on. So a restored belief is clamped:
its upper bound says unlikely rather than impossible, its lower bound says
likely rather than proven, and its confidence is halved. The first fresh
observation clears all of it. Clamping is what makes keeping these beliefs
better than throwing them away at startup.

**An ambiguous failure is recorded against the node pair.** The model wants to
key on a directed channel, because the quantity it tracks is the balance on one
side of one funding output. Under non-strict forwarding that is not always what
the evidence supports: a node asked to forward over one channel may use any
channel it has to the same peer, and the onion failure names neither. So when
the graph shows more than one channel between a pair, the observation is
written about the pair instead, at the granularity mission control has always
used. Pairs with a single channel, which is most of them, keep the full
resolution.

**Searching costs more than Dijkstra does.** Every rung of the shard ladder
runs its own search, and each search may keep up to two dozen labels per node.
The graph reads are shared across the ladder and the search is bounded on hops,
labels, and total expansions, but the worst case is still well above one
shortest path query. This is the main reason the router is off by default.

**The constants were selected, not derived.** The probability model, the retry
ladder, and the scoring weights come from an evolutionary search against a
payment simulator, scored on a real 12,000 node mainnet graph snapshot and on
synthetic topologies. They are documented for what they do rather than for why
those particular numbers are right, because for most of them nobody can say.
Some are surely fitted to the simulator that produced them.

## Where the code lives

| File | What is in it |
|---|---|
| `routing/interval_belief.go` | the interval and the probability model |
| `routing/interval_store.go` | the node wide store and its flushing |
| `routing/interval_store_sql.go` | the durable backing |
| `routing/interval_pathfind.go` | the label setting search |
| `routing/interval_session.go` | the shard ladder and the session state |
| `routing/interval_session_source.go` | session construction and the fallback |
| `routing/interval_config.go` | the search bounds and their defaults |
