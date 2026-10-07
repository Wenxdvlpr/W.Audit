# Real-world smoke summary — 0.3.0a0

Read-only offline scans; target code and dependencies were not executed. Commit IDs identify the shallow snapshots used.

| Project type | Snapshot | Files | Findings (HIGH / MEDIUM / LOW) | Outcome |
| --- | --- | ---: | --- | --- |
| Python web — Flask | `pallets/flask` `d086db8` | 236 | 0 / 16 / 0 | Completed, no crash. Findings were manual-review heuristics; most credential-pattern matches occur in documentation/examples. |
| Node/web — Express | `expressjs/express` `9efc29e` | 214 | 0 / 5 / 1 | Completed, no crash. Test-directory sink matches are intentional test cases; other MEDIUM findings remain manual review. |
| Container/infrastructure — hello-world | `docker-library/hello-world` `522bcd2` | 35 | 0 / 0 / 3 | Completed, no crash. LOW findings concern mutable GitHub Action references. |

No HIGH findings required confirmation or downgrade. The sample remains too small to establish broad false-positive rates. Built-in coverage is partial; optional external scanners were not run in this smoke.
