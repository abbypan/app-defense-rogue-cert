# ASPin protocol, model, and evaluation specifications

These documents expand the compact material in Appendices D and E. They
describe existing symbolic models, saved verification results, and measurement
protocols, not additional proofs or Android experiments.

- [Model setup, network attacks, cross-app use, cache, and fail-closed behavior](proverif-models.md)
- [Certificate changes, migration, key rotation, and lifecycle boundaries](proverif-lifecycle.md)
- [Evaluation controls, timing definitions, cache, and API robustness](evaluation-protocol.md)
- [Cross-app, fail-closed, public-CA, migration, and key-rotation experiments](evaluation-scenarios.md)

The document order follows the paper's Security Analysis and Evaluation. Model assumptions
and the Android prototype gap remain stated in Appendix C; moving trace-level
details here does not remove or strengthen those assumptions.

From the repository root, check documentation/model/result consistency with:

```sh
python3 proverif/check_consistency.py
python3 check-implementation-consistency.py
```

The model sources are in [proverif/](../proverif/), and saved query outputs are in
[proverif/result/](../proverif/result/). To actually rerun the proofs in an
environment with ProVerif installed, use `bash proverif/run.sh`. The consistency
checks alone do not rerun ProVerif.
