# Contributing

Open an issue describing the check, evidence and false-positive risks. New rules need a vulnerable and a secure fixture. Keep target code unexecuted, report only redacted evidence, and document limitations. Run `PYTHONPATH=src python3 -m unittest discover -s tests -v` before proposing a change. Do not include real credentials in fixtures or issues.

## Developer Certificate of Origin

Contributions use the [Developer Certificate of Origin 1.1](https://developercertificate.org/) process rather than a separate contributor license agreement. By submitting a contribution, you certify that you have the right to submit it under the project's Apache-2.0 license and that its provenance is appropriate under the DCO. Add a `Signed-off-by` trailer to each commit with `git commit -s`; use a name and email you are authorized to disclose publicly. The sign-off is part of the public contribution record.

The contributor retains authorship of their contribution under applicable law. Do not submit third-party code unless its license and your right to contribute it are clear.
