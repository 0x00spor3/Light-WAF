## What

<!-- What this changes and why. Link the issue: "Closes #123". -->

## How it was tested

<!-- Tests added or run; for detection changes, the corpus cases (attack + near-miss benign). -->

## Checklist

- [ ] `cargo clippy --workspace --all-targets -- -D warnings` and `cargo test --workspace` pass locally
- [ ] New functionality or a bug fix comes with tests
- [ ] New config is default-off, documented in the example config and validated at load time
- [ ] `CHANGELOG.md` has an entry under `[Unreleased]` (for user-visible changes)
- [ ] Commits are signed off (`git commit -s`, see CONTRIBUTING.md)
