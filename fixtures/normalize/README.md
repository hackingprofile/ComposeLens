# Normalization fixtures

Each field has an equivalent short/long (or list/map, string/CMD-SHELL) pair that must compare equal after `normalize.FromMerge`, plus an intentionally non-equivalent pair.

Command string vs exec list is **not** an equivalent pair (Compose Specification shell vs exec). The equivalent command pair is flow-sequence vs block-sequence of the same argv.

No secret values are stored in these files. Secret probes run in-process in tests.
