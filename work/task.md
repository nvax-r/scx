  # Task: SCXI v2 format break — move event IDs out of section-ID space

  > **Premise:** This is a deliberate on-disk format break. We are fixing the root cause of the parser collision
  bug, not papering over it with more heuristics.
  >
  > In v1, section IDs live in `0x0001..0x0003` and event IDs live in `1..5`, which means they share the same low
  numeric space. That is structurally wrong. The reader currently has to guess whether it is looking at an event TLV
  header or a section header, and the guess already fails for `SECTION_PROCS(sec_len=40)` when the trace contains
  exactly two unique PIDs.
  >
  > We are not keeping backward compatibility. After this task, the in-tree reader supports **v2 only**. Old v1
  traces are intentionally unsupported.

  ## Status going in

  - `scheds/rust/scx_invariant/src/bpf/intf.h` defines:
    - `EVT_RUNNING = 1`
    - `EVT_STOPPING = 2`
    - `EVT_RUNNABLE = 3`
    - `EVT_QUIESCENT = 4`
    - `EVT_TICK = 5`
  - `scheds/rust/scx_invariant/src/output.rs` writes file header `VERSION = 1`.
  - `scheds/rust/scx_invariant/analysis/reader.py` accepts event candidates using a loose heuristic:
    - event type in `{1..5}`
    - payload size in `{88, 40, 32, 64}`
  - `scheds/rust/scx_invariant/src/output.rs` writes section IDs as:
    - `SECTION_TOPOLOGY = 0x0001`
    - `SECTION_PROCS = 0x0002`
    - `SECTION_EVENTS = 0x0003`
  - `PLAN.md` already documents this as a known issue and says the real fix is v2 with event IDs starting at
  `0x0100`.

  ## Goal

  Make the `.scxi` format structurally unambiguous by moving event IDs out of the section-ID range and declaring a
  hard v2 format break.

  Success means:

  - new traces are written as **version 2**
  - event IDs no longer overlap section IDs
  - the reader supports **version 2 only**
  - the two-PID process-table collision is impossible by construction
  - no trace payload layout changes are introduced
  - no scheduler behavior changes are introduced

  ## New v2 event ID assignments

  In `scheds/rust/scx_invariant/src/bpf/intf.h`, renumber the event enum to:

  - `EVT_RUNNING   = 0x0100`
  - `EVT_STOPPING  = 0x0101`
  - `EVT_RUNNABLE  = 0x0102`
  - `EVT_QUIESCENT = 0x0103`
  - `EVT_TICK      = 0x0104`

  Section IDs stay unchanged:

  - `SECTION_TOPOLOGY = 0x0001`
  - `SECTION_PROCS    = 0x0002`
  - `SECTION_EVENTS   = 0x0003`

  ## MUST do

  1. Update the event ID enum in `scheds/rust/scx_invariant/src/bpf/intf.h` to the new `0x0100..0x0104` range.

  2. Rebuild the producer side with the new IDs by updating any emitted `evt->hdr.event_type` users through the
  shared enum in:
     - `scheds/rust/scx_invariant/src/bpf/main.bpf.c`

  3. Bump the on-disk format version in `scheds/rust/scx_invariant/src/output.rs`:
     - change `const VERSION: u16 = 1;` to `2`

  4. Keep `src/output.rs` simple:
     - continue reading `event_type` from offset 20 of the raw payload
     - continue writing that value into the TLV prefix
     - do **not** add any remap table or translation layer in the writer

  5. Make `scheds/rust/scx_invariant/analysis/reader.py` **v2-only**.
     - reject any file whose header version is not `2`
     - fail early with a clear error message
     - do not keep any compatibility path for v1

  6. Tighten event parsing in `analysis/reader.py`.
     Replace the loose `KNOWN_SIZES` check with an exact per-type size table:

     - `EVT_RUNNING   -> 88`
     - `EVT_STOPPING  -> 88`
     - `EVT_RUNNABLE  -> 40`
     - `EVT_QUIESCENT -> 32`
     - `EVT_TICK      -> 64`

     A candidate event must satisfy both:
     - event type is a known v2 event ID
     - payload length exactly matches that event type’s ABI size

  7. Update `EVT_NAMES` and any other reader-side constant tables to the new v2 values.

  8. Add a reader regression test as a standalone Python script:
     - **Create:** `scheds/rust/scx_invariant/analysis/test_reader.py`
     - use Python stdlib only (`unittest`, `tempfile`, `struct`, `subprocess` if needed)
     - run it as:
       - `python3 scheds/rust/scx_invariant/analysis/test_reader.py`

  9. The regression test must cover at least these two cases:

     **Case A — v2 two-proc trace parses correctly**
     - synthesize a minimal valid v2 `.scxi` file
     - include:
       - valid 64-byte header with `version = 2`
       - topology section
       - events section
       - at least one valid event using the new v2 event IDs
       - process table section with exactly 2 proc entries (`sec_len = 40`)
     - assert:
       - the process table is parsed as 2 entries
       - no phantom extra event appears
       - event count matches what was written

     **Case B — v1 trace is rejected**
     - synthesize a minimal valid v1-style file with `version = 1`
     - assert:
       - the reader exits/fails with a clear unsupported-version error
       - it does not silently parse the file

  10. Update `scheds/rust/scx_invariant/PLAN.md`.
      This is mandatory. At minimum:
      - remove the current wording that presents the shared numeric-space collision as an active known issue in the
  current format
      - document that v2 fixes it by renumbering event IDs to `0x0100+`
      - update the event-type table in the format section to the new values
      - if any prose still says the reader relies on payload-size heuristics, fix it

  11. Update `work/notes.md` with:
      - the root cause
      - the exact v2 event ID assignments
      - the decision to drop v1 reader support
      - any test traces used for validation

  12. Update `work/changelog.md` with a concise entry stating:
      - SCXI format bumped to v2
      - event IDs moved to `0x0100+`
      - reader is now v2-only
      - the section/event ID collision class is removed structurally

  ## MUST NOT do

  - Do **not** keep backward compatibility for v1 in `analysis/reader.py`.
  - Do **not** introduce dual-version decode paths.
  - Do **not** renumber section IDs.
  - Do **not** change event payload layouts or field order.
  - Do **not** change event struct sizes.
  - Do **not** change ringbuf payload contents beyond the event ID values carried in the header.
  - Do **not** change scheduler behavior.
  - Do **not** change PMU behavior.
  - Do **not** add `EVT_TICK` emission as part of this task.
  - Do **not** mix this task with unrelated reader cleanup, analyzer work, or Task 7 feature work.
  - Do **not** “solve” this only by adding more parsing heuristics while keeping the old ID space.
  - Do **not** add a writer-side translation shim that preserves old event IDs in any path.

  If anything outside the files listed below appears necessary, stop and document why in `work/notes.md` before
  proceeding.

  ## Files in scope

  - **Modify:** `scheds/rust/scx_invariant/src/bpf/intf.h`
  - **Modify:** `scheds/rust/scx_invariant/src/bpf/main.bpf.c`
  - **Modify:** `scheds/rust/scx_invariant/src/output.rs`
  - **Modify:** `scheds/rust/scx_invariant/analysis/reader.py`
  - **Create:** `scheds/rust/scx_invariant/analysis/test_reader.py`
  - **Modify:** `scheds/rust/scx_invariant/PLAN.md`
  - **Modify:** `work/notes.md`
  - **Modify:** `work/changelog.md`

  ## Files expected to remain unchanged

  - `scheds/rust/scx_invariant/src/main.rs`
  - `scheds/rust/scx_invariant/src/pmu.rs`
  - `scheds/rust/scx_invariant/src/recorder.rs`
  - `scheds/rust/scx_invariant/src/cgroup.rs`
  - `scheds/rust/scx_invariant/src/bpf/intf.h` field layouts other than the numeric event ID assignments
  - `scheds/rust/scx_invariant/src/bpf/main.bpf.c` scheduling logic other than using the new enum values

  ## Invariants

  These must still be true after the change:

  - `enqueue` remains the passthrough insert into `SCX_DSQ_GLOBAL`
  - `select_cpu` remains attribution-only
  - `running` / `stopping` remain the PMU-producing path
  - cgroup filtering remains unchanged
  - the binary trace still consists of:
    - fixed 64-byte file header
    - topology section
    - events section
    - process table section
  - only the file version and event ID numeric space change

  ## Validation gates

  1. `cargo fmt --check`

  2. `cargo check --profile ci --locked -p scx_invariant`

  3. `cargo build --profile ci --locked -p scx_invariant`

  4. `python3 scheds/rust/scx_invariant/analysis/test_reader.py`

  5. Generate a fresh v2 trace with exactly two unique PIDs, then decode it:
     - `sudo target/ci/scx_invariant record -o /tmp/t2.scxi -- bash -c 'sleep 1; wait'`
     - `python3 scheds/rust/scx_invariant/analysis/reader.py /tmp/t2.scxi`

     Expected:
     - process table is present
     - no phantom extra event appears
     - no parser ambiguity around the process-table section

  6. Confirm the reader rejects a v1 trace clearly.
     Any old v1 trace is acceptable for this check.
     Expected:
     - fast failure
     - explicit unsupported-version error
     - no partial decode

  7. Confirm the diff is limited to the scoped files above.

  ## Expected outcome

  After this task:

  - `.scxi` is a **v2-only** in-tree format
  - section IDs and event IDs no longer share the same numeric space
  - the two-PID process-table collision is eliminated at the format level
  - the reader is stricter and simpler
  - old v1 traces are intentionally unsupported by the in-tree reader
  - no scheduler or PMU semantics have changed