# Adopting this into an organization's standard path

This repository proves its controls with its own tests and its own pipeline. An organization that adopts it will
have a prescribed path of its own: a standard agent framework and runtime, a governed model route, a shared
delivery workflow, a deployment platform, required scanners and signed attestations. Evidence from this
repository's pipeline does not stand in for evidence from that path. This page is the list of what has to be
shown there, and what exists here to start from.

The rule for this page: a row is only marked done when the adopting organization's own system produced the
evidence. Until then it says what the stand-in is.

## What the path usually prescribes, and where this repository stands

| The standard path usually requires | What is here | To be shown on the standard path |
|------------------------------------|--------------|-----------------------------------|
| The standard agent framework on the managed agent runtime | `agent/app.py` on a standard framework, container image built and smoke tested in CI. The production stage refuses any other shape without a recorded approval | A deployment to the organization's runtime, from its template |
| Model access only through the governed gateway | `MODEL_ROUTE=gateway`. With live evidence a direct call is refused in code unless an approval reference is recorded | A call through the organization's gateway with its credentials, and the gateway's own logs |
| The shared delivery workflow, not a private one | `.github/workflows/ci.yml` is a private stand-in with the same kinds of gate | The repository onboarded to the shared workflow, with a passing run |
| The deployment platform and its promotion rules | `template.yaml` and `agent/Dockerfile` as inputs. `deploy.yml` is a stand-in and is inert | A promotion through the platform, with its approvals |
| Secret scanning | Full-history secret scan in CI | The required scanner's report |
| Static code quality analysis | Lint and static security analysis in CI | The required tool's quality gate result |
| Application security testing | Static analysis, dependency audit and image scan in CI | The required tool's findings, triaged |
| Software bill of materials and build provenance | Checksummed artifact with a software bill of materials | Signed attestations from the required attestation service |
| Real identity | Token verification tested with locally generated keys | One real token verified end to end in a non-production environment |
| Logging to the AI and security log platforms | One structured audit line and metrics per request | Those lines arriving in the required platforms, with retention confirmed |
| Evaluation before release | Golden cases and an adversarial suite, scripted model | The same suites run against the approved model through the governed route |
| A security review | Threat model inputs in `docs/ARCHITECTURE.md` and `docs/RISKS.md` | The review's outcome and any conditions |

## How to use it

1. Give this page and `docs/STATUS.md` to the owner of the standard path and ask which rows apply and which tools they mean.
2. Onboard the repository to the shared workflow first. Most other rows produce their evidence from there.
3. As each row is evidenced by the organization's own system, record where the evidence lives in `docs/STATUS.md`.
4. Remove the stand-in job it replaces, so there is one source of truth for each gate.

The stage guard in `src/stage.py` is what keeps the code honest in the meantime: the default stage accepts
synthetic data only, and the production stage accepts only the supported shape and route.
