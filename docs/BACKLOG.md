# Backlog

## Stylometry authorship-pair calibration dataset

**Priority:** Low / non-urgent  
**Status:** Future task — calibration remains intentionally gated off until this is complete.

Source or construct a labeled authorship-pair dataset for the stylometry evaluator. The dataset must contain both:

- same-author text pairs; and
- different-author text pairs.

The data should document provenance, licensing/usage permissions, language, minimum text lengths, author and pair counts, and any train/validation/test split. Avoid leakage between splits (for example, pairs from the same author should not cross evaluation boundaries in a way that inflates performance).

### Acceptance criteria

1. A reproducible, documented dataset is available to the project or can be generated from published data.
2. The dataset is formatted for `scripts/evaluate_stylometry.py` (`text_a`, `text_b`, `same_author`).
3. Evaluation produces a committed calibration artifact containing the selected threshold, validation-pair count, false-match rate, true-match rate, true-negative rate, and reference statistics.
4. The artifact is configured through `STYLOMETRY_CALIBRATION_FILE` only after review of its provenance and evaluation design.
5. Until these criteria are met, stylometric results must continue to be reported as uncalibrated and must not produce same-author match decisions.

