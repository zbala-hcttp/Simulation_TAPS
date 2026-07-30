Signing, combining and tracing simulation in classical TAPS.

Four binaries talk over localhost TCP: `authority` (8080), `combiner` (8081),
`signer`, `tracer`. `benchmark` drives the whole thing across several (N, T)
scenarios and writes three CSVs.

## Running

Build first:

```bash
cargo build --release --bins
```

Full benchmark suite (spawns everything itself):

```bash
cargo run --release --bin benchmark
```

A single run, from the crate root, each in its own terminal — authority first,
then combiner, then tracer, then one signer per id `0..N-1`:

```bash
./target/release/authority 10 6
```

```bash
./target/release/combiner
```

```bash
./target/release/tracer
```

```bash
./target/release/signer 0
```

## Trust anchor

At startup the authority writes its identity and transport public keys to
`taps_authority.pub` in the working directory, before it starts listening. Every
other actor reads that file and pins those keys.

This is the root of the chain of trust, so **all actors must run from the same
working directory as the authority**. Verifying a package against a key carried
inside that same package proves nothing, so the authority's key has to arrive out
of band; in a real deployment that would be a pinned config or a CA, and here the
file stands in for it. Every other key — signer, combiner and tracer identity and
transport keys — is then distributed by the authority inside signed, encrypted
packages, so no actor ever trusts a key a peer claims for itself.

## Benchmark output

- `benchmark_results_signers.csv` — `N,T,Signer_ID,Phase,Time_Microseconds`
- `benchmark_results_combiner.csv` — `N,T,Phase,Time_Microseconds`
- `benchmark_results_tracer.csv` — `N,T,Phase,Time_Microseconds`

Timers cover computation only. Waiting for other processes to start and connect
is excluded, so `Setup` measures key generation plus package verification and
decryption, and `Aggregation` / `Collect Shares` accumulate only the per-message
verify-decrypt-deserialize cost, not time blocked on a socket.
