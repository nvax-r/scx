# Glossary

- `sched_ext`: Linux scheduler class allowing BPF-defined schedulers.
- `SCX`: Common shorthand for the `sched_ext/scx` repository and ecosystem.
- `struct_ops`: Kernel/BPF mechanism used to register scheduler operation callbacks.
- `BPF skeleton`: Generated userspace bindings for BPF objects and maps.
- `DSQ`: Dispatch queue concept used by sched_ext schedulers.
- `SCXI`: Binary trace format emitted by `scx_invariant`.
- `ring buffer`: BPF-to-userspace event channel used by `scx_invariant` recorder.
- `topology`: CPU metadata (CPU ID, LLC ID, NUMA ID, capacity, max frequency).
- `veristat`: Tooling for BPF verifier statistics used in CI and optimization workflows.
- `nextest`: Rust test runner used in CI for workspace unit tests.
- `passthrough scheduler`: A scheduler that minimally intervenes in scheduling decisions, often used for instrumentation/profiling.
- `profiling-first`: Principle that trace fidelity and observability are primary, while scheduling policy changes are avoided by default.

