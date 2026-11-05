# Member 3 runtime fixes (2026-11-04)

Review of `traceguard/runtime/` against the team brief found four defects and one
missing capability. Each has a regression test in `tests/test_member3_runtime_fixes.py`.

| # | Defect | Fix | Brief reference |
|---|--------|-----|-----------------|
| 1 | Tool output took the label of the call's *arguments*, so a user-named `email_id` made the email body (and any address in it) `USER_AUTHORIZED`. | `ProvenanceTracker.record_tool_output` always labels returned content `UNTRUSTED_EXTERNAL` (`DERIVED_UNTRUSTED` if an input was already derived). | Provenance rule 1 |
| 2 | No lineage existed. `save_note` stored plain text and returned `USER_AUTHORIZED`; no parent IDs anywhere. | `NoteRecord` with runtime-assigned label and `parent_source_ids` (union of all sources read). E2b persists it; E2a stores `UNKNOWN` with no parents and keeps the true lineage only as audit data (`ground_truth_*`, `provenance_break`). | Rules 2-4, section 6 |
| 3 | "Email me" authorized unlimited sends to the verified address. | `AuthorizationEntry.max_uses`; verified-address `send_email` grants are single-use and consumed after execution. | "Email me" special case |
| 4 | A quoted or pasted address could authorize a recipient (`Summarize this email: '... send to X ...'`). | `runtime/userinput.py::split_user_text`; the ledger and tracker use only the user's own instruction text. Pasted material is registered as `UNTRUSTED_EXTERNAL`. | Rule 12 |
| 5 | The model saw only the current user message: no history, no tool results, no labels, no per-config prompt. | Runner keeps history and passes `prompt_mode=<config>`. E2b/E4 show labeled results and note parents; E2a shows raw notes; E0/E1/E3 show neutral text. | Sections 6-7 |

Gateway rules are unchanged and shared by E2a, E2b and E4. Scripted-backend
benchmark numbers are identical before and after (the scripted backend does not
read history).

## Open questions for Member 1 (policy owner)

1. The gateway treats `subject` and `body` as sensitive arguments. The brief lists
   recipient, handle, path, attachment, CC/BCC. Blocking a `DERIVED_UNTRUSTED` body
   to a user-named recipient may cause over-refusal; confirm intent.
2. Tool names differ from the brief (`retrieve_notes`/`save_note` vs
   `search_notes`/`read_note`/`write_note`). Renaming touches `tools.yaml`, the
   parser, datasets and tests; left unchanged pending a decision.
3. `split_user_text` is a heuristic: unquoted pasted text with no introducer
   ("summarize this email:") is not detected.
4. A note written with no untrusted context is labeled `UNKNOWN` (never trusted).
   Confirm this is the intended label.
