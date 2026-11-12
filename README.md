# freenet-imageboard

An anonymous imageboard for [Freenet](https://freenet.org): boards, threads,
replies and images, with no servers, no accounts and no moderators.

An independent project, not affiliated with the Freenet project.

## Status

Design stage. No contract, delegate or UI exists yet. The repository holds
this description and the benchmark harness behind the numbers below.

Two things are unresolved:

- Posting depends on a ring-signing operation that the
  [Ghostkey Vault](https://github.com/freenet/ghostkeys) does not have yet
  ([freenet/ghostkeys#65](https://github.com/freenet/ghostkeys/issues/65)).
  Without it the design cannot launch on the public network.
- The thread catalog has no working design. See
  [Catalog ordering](#catalog-ordering-open-problem).

## Design

- **No accounts.** Posting requires a [ghost key](https://freenet.org/ghostkey/);
  reading requires only a Freenet node.
- **Per-thread IDs.** A poster is recognisable inside one thread and
  unlinkable across threads. One ghost key gives exactly one ID per thread.
- **No authority.** A board is a set of immutable parameters. Nobody holds a
  key over it, including whoever created it.
- **Removal by vote.** Reports from participants collapse a post, then
  remove it and its images, then ban the ID within the thread.
- **Images on demand.** A reader's node fetches an image only when the
  reader asks for it.

### Per-thread IDs

The ID is the key image of a linkable ring signature (LSAG) over ghost
public keys on edwards25519:

```
I = a * Hp(caller || "post" || thread_anchor)
```

where `a` is the ghost key's secret scalar, `Hp` hashes to a prime-order
point, and `thread_anchor` is an identifier from the thread's parameters. It
is not the contract's address, which changes whenever the contract code does. The signature proves that the signer holds one of the ring's keys
without showing which, and `I` is the same for every signature by that key in
that thread. Contracts check ring members against a registry of ghost key
certificates.

One ring signature binds a per-thread session key; posts and votes are then
ordinary Ed25519 signatures by that key.

The ghost key stays in the Ghostkey Vault. The application receives only
signatures scoped to itself.

### Catalog ordering (open problem)

Contracts have no clock, a timestamp supplied by a poster cannot be checked,
and with no keeper or owner nobody can attest the time. A board still needs
to drop old threads and keep its catalog small enough to validate.

Ordering the catalog by a logical height that must be free of gaps, so that
a forged jump ahead is refused, looks like a solution and is not. It breaks
Freenet's merge laws: a contract must merge any two states its own
validation accepts, and the union of an honest catalog and a forged one
would be refused. It also lets one writer's value decide whose entries are
discarded, which is the pattern Freenet's guidance for contract authors
warns against.

What a replacement has to satisfy:

- every merge of two valid states succeeds and is order-independent;
- a value a writer supplies ranks only that writer's own entries;
- the catalog has a hard size bound, and stale entries eventually leave it.

Under consideration: a fixed number of catalog slots per ghost key, bounded
by a count cap on a key the entry itself determines, with ranking by
activity done in readers instead of in the contract; and a coarse epoch
taken from the issue month recorded in ghost key certificates, if those
turn out to be usable as a clock. Neither is verified.

### What it does not do

- It does not hide a poster's IP address from neighbouring peers.
- It cannot ban a person across threads; IDs are unlinkable by design.
- It cannot restore removed content or overrule a vote.
- A board cannot change its rules after creation.
- It does not remove the central issuer: ghost keys are minted by Freenet's
  donation service, so new posters depend on that service being available.

## Ring verification cost

A contract verifies every ring signature it stores, so verification time
bounds ring size and the number of IDs per thread.

One LSAG verification, including decompression of the ring keys and the
subgroup check on the key image. AMD FX-9590 (2013, no AVX2), one core.
Rust 1.99.0, `curve25519-dalek` 4.1 with its 32-bit backend, wasmtime 47 with
the engine settings of `freenet-core` at 83d3397. Median of 7 runs.

| Case | Native | wasmtime, Freenet settings | wasmtime, defaults |
|---|---|---|---|
| Ed25519 `verify_strict` | | 0.43 ms | 0.35 ms |
| Ring of 16 | 4.0 ms | 12.6 ms | 10.3 ms |
| Ring of 32 | 7.8 ms | 24.7 ms | 20.2 ms |
| Ring of 64 | 16.0 ms | 48.9 ms | 40.2 ms |
| Ring of 128 | 31.4 ms | 96.7 ms | 79.9 ms |

About 0.77 ms per ring member under Freenet's settings. With rings of 16 and
80 IDs per thread, a full thread validates in about 1.3 s on that CPU,
against a 5 s limit per contract call.

The numbers come from a standalone wasmtime host, not from a Freenet node,
and the verifier is unoptimised. The harness is in
[`spikes/s1-ring-verify`](spikes/s1-ring-verify).

## Layout

| Path | Contents |
|---|---|
| `spikes/` | Throwaway experiments. Code here exists to answer one question and is not used by the product. |

## License

Licensed under either of [Apache License 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT), at your option.
