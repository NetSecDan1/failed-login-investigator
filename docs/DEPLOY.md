# Deploying

Everything lives in one CloudFormation stack named `fli-proto`: an S3 bucket, a Bedrock Guardrail,
an IAM role, a Lambda function and a log group. All options below end in the same stack.

## Before any option

1. **Use a sandbox or non-production account.** This is a prototype.
2. **Anthropic model access.** In the Bedrock console open Model catalog, pick a Claude model and submit the
   use case details if prompted. Check with:
   ```bash
   aws bedrock-runtime converse --model-id us.anthropic.claude-sonnet-5-5 \
     --messages '[{"role":"user","content":[{"text":"Reply OK"}]}]' \
     --inference-config maxTokens=5 --query 'output.message.content[0].text' --output text
   ```
3. **Pick a model ID.** List what the region offers:
   ```bash
   aws bedrock list-inference-profiles \
     --query "inferenceProfileSummaries[?contains(inferenceProfileId,'anthropic')].inferenceProfileId" --output text
   ```
   `us.` profiles keep inference in US regions. `global.` profiles can route anywhere. Check your data rules.
4. **Permissions for whoever deploys:** CloudFormation, S3, Lambda, IAM role creation, Bedrock Guardrails, CloudWatch Logs.

## Option A: AWS CloudShell (fastest, no local setup)

Best for a first look. CloudShell already has the AWS CLI, Python and zip, signed in as your console user.

1. Open CloudShell in the target region.
2. Get the code in. Either upload a zip of this repo (Actions, Upload file, then `unzip`), or clone with a
   fine-grained token that has read access to this repo.
3. Run:
   ```bash
   cd failed-login-investigator
   ./deploy.sh us.anthropic.claude-sonnet-5-5
   ./run_tests.sh
   ```

## Option B: Local AWS CLI

Best for day-to-day development.

```bash
aws sso login --profile sandbox          # or however you authenticate
export AWS_PROFILE=sandbox AWS_REGION=us-east-2
python tools/make_data.py && python -m pytest -q tests
./deploy.sh us.anthropic.claude-sonnet-5-5
./run_tests.sh
```

Needs AWS CLI v2, Python 3.11 or newer, `zip`, and bash (Git Bash or WSL on Windows).

## Option C: CloudFormation console (click path)

Best when you want to see every resource before it is created.

1. CloudFormation, Create stack, upload `template.yaml`, stack name `fli-proto`, set `ModelId`.
2. Acknowledge the IAM capability and create. The function is created with placeholder code.
3. Upload code and data. The console cannot do this from the template alone, so finish with:
   ```bash
   python tools/make_data.py
   aws s3 sync data/ s3://<Bucket output>/ --delete --exclude "skills/*"
   aws s3 sync skills/ s3://<Bucket output>/skills/ --delete
   (cd src && zip -qr ../fn.zip .)
   aws lambda update-function-code --function-name fli-proto-fn --zip-file fileb://fn.zip
   ```
   Or zip `src/` and upload it on the Lambda console Code tab, and upload the `data/` folders and `skills/` in the S3 console.

## Option D: GitHub Actions with OIDC (no stored keys)

Best once more than one person deploys. `.github/workflows/deploy.yml` runs on pushes to `main` and on demand,
and skips itself until the repository variable `AWS_DEPLOY_ROLE_ARN` is set.

**Check first:** some AWS Organizations block IAM OIDC providers with a service control policy. If
`aws iam list-open-id-connect-providers` returns an explicit deny that names a service control policy, this
option is not available in that account. Do not work around it. Use another option or ask the organization owner.

1. Create the provider, the deploy role and the function boundary with the template in `infra/`:
   ```bash
   aws cloudformation deploy --stack-name fli-github-oidc --template-file infra/github-oidc.yaml \
     --capabilities CAPABILITY_NAMED_IAM
   ```
   Pass `--parameter-overrides CreateProvider=false` if the account already has the GitHub provider.
2. What that role can do: manage the one stack `fli-proto` and its resources. It can create or change the
   function role only when the role carries the `fli-proto-function-boundary` policy, so it cannot mint a role
   with more than read-only data access, model invoke and its own logs. It is trusted for this repo's `main` branch only.
3. If the stack already exists without the boundary, attach it once as an administrator, then let the pipeline keep it:
   ```bash
   aws iam put-role-permissions-boundary --role-name <function role name> --permissions-boundary <BoundaryArn output>
   ```
4. Set repository variables `AWS_DEPLOY_ROLE_ARN` and `AWS_BOUNDARY_ARN` from the stack outputs. Optional:
   `AWS_REGION`, `BEDROCK_MODEL_ID`.
5. Push to `main`, or run the workflow from the Actions tab. It runs the tests, deploys, runs the six smoke
   cases, then the 15 skill evaluation cases.

**Status:** the templates pass lint. This path has not been deployed. The first attempt in the test account
was stopped by an organization service control policy on OIDC providers.

## Option E: Your organization's pipeline

For an enterprise golden path, treat `template.yaml` as the reference, not the delivery vehicle. Port the five
resources to the approved IaC tool and pipeline, keep the IAM statements as written, and carry the tests and
`run_tests.sh` cases over as pipeline gates. Decide these before porting: approved models and regions, where
audit logs must land, and how the function reaches Splunk, Databricks and IIQ.

## Turning on the HTTP API

The API is off by default. Passing an issuer creates an HTTP API with a JWT authorizer, two routes
(`GET /accounts`, `POST /investigations`) and a global throttle. **This path passes template lint and unit tests
with simulated API events. It has not been deployed or called with a real token.**

```bash
./deploy.sh <model-id> \
  JwtIssuer=https://login.microsoftonline.com/<tenant-id>/v2.0 \
  JwtAudience=<application client ID or ID URI your tokens carry> \
  CallerClaim=<claim that matches your ownership keys> \
  AllowTestClaims=false
```

- **Issuer and audience** must equal the `iss` and `aud` in a real access token. Decode one first and copy the values.
- **Caller claim:** Entra tokens do not carry an employee number unless you add it as an optional or mapped
  claim. `oid` and `preferred_username` are present by default. Whatever you choose must be the key used in the ownership source.
- **`AllowTestClaims=false`** makes the function ignore any caller passed in the request. Leave it `true` only while testing by direct invoke.
- The endpoint is public by default. Put it behind your network controls before real use.

Call it:

```bash
curl -H "Authorization: Bearer $TOKEN" "$API/accounts"
curl -H "Authorization: Bearer $TOKEN" -H "content-type: application/json" \
  -d '{"account":"svc-batch01","window_hours":24}' "$API/investigations"
```

Status codes: 200 ok, 400 bad input, 401 no verified caller, 403 not yours or nothing owned, 503 ownership source down.

Real evidence sources are covered in [`BACKENDS.md`](BACKENDS.md).

## Verify

`./run_tests.sh` prints one line per case. Expected once model access works:

| Case | Expect |
|------|--------|
| `owned_stale` | `status=ok`, `class=stale-credential`, `esc=False` |
| `owned_spray_inj` | `status=ok`, `class=suspicious-source-escalate`, `esc=True`, or facts only if the guardrail intervenes |
| `owned_no_data` | `status=ok`, `class=insufficient-evidence` |
| `not_owned` | `status=denied`, `reason=out_of_scope` |
| `tier0_owned` | `status=denied`, `reason=out_of_scope` |
| `unknown_caller` | `status=denied`, `reason=scope_empty` |

Without model access the first three show `notes=['summary_withheld:model_error...']` and the denials still pass.

For the full skill evaluation, run `python tools/run_evals.py` (15 cases, one model call each).

Audit lines: `aws logs tail /aws/lambda/fli-proto-fn --since 10m | grep AUDIT`

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `Model use case details have not been submitted` | Anthropic first-use form not submitted | Submit it in the Bedrock Model catalog |
| `<model> is not available for this account` | Model not offered to the account yet | Submit the form, or pass a different model ID to `deploy.sh` |
| `KMSAccessDeniedException` on invoke | A role-level explicit deny that covers `kms:Decrypt` | Keep `kms:Decrypt` in the `NotAction` list, as in `template.yaml` |
| `summary_withheld:guardrail_intervened` | Guardrail blocked input or output | Expected for hostile input. For normal input, review the guardrail trace and tune the topic definition |
| `validator_reject_*` notes | Model named something not in the evidence, or a heuristic false reject | Read the note. Extend `BENIGN_RE` in `src/validator.py` only for clearly harmless tokens |

## Remove

```bash
./teardown.sh
```

Empties the versioned bucket and deletes the stack. Nothing outside the stack was created.
