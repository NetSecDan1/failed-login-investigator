# Deploying from the AWS console

A click-by-click path using the console only: CloudFormation, S3, Lambda and CloudWatch. It creates the same
stack as every other option in [`DEPLOY.md`](DEPLOY.md), with synthetic data, so nothing here touches a real
identity or log system.

**Status: the template passes lint and the function package is built and checked in CI. This exact click path
was last exercised on an early build. Console screens change, so labels may differ slightly.**

## Before you start

| You need | Why |
|----------|-----|
| A sandbox or non-production account and the region you will use | This is a prototype |
| Console rights for CloudFormation, S3, Lambda, IAM role creation, Bedrock guardrails and CloudWatch Logs | The stack creates one of each |
| Access to an Anthropic model in Bedrock in that region | Without it you still get facts, with the summary withheld |
| The console bundle | The files you will upload |

**Get the console bundle.** In the repository open **Actions**, choose the latest successful **ci** run on `main`,
and under **Artifacts** download `console-bundle-<commit>`. Unzip it. You should see:

```
template.yaml          the stack
function.zip           the function code, already packaged
bucket/                skills/, ownership/, evidence/   (goes into the data bucket)
test-events/           six requests to try
DEPLOY_CONSOLE.md      this guide
```

**Find a model ID.** In the Bedrock console open **Inference profiles** (under Infer). Copy the ID of an Anthropic
Claude profile, for example one starting with `us.anthropic.`. If Bedrock asks for use case details the first time
you use an Anthropic model, that form has to be submitted by the account owner before the model will answer.

## 1. Create the stack

1. Open **CloudFormation**. Check the region shown in the top bar.
2. **Create stack**, then **With new resources (standard)**.
3. **Choose an existing template**, **Upload a template file**, choose `template.yaml`, **Next**.
4. **Stack name:** `fli-proto`. The name matters: other steps and the cleanup assume it.
5. **Parameters:** paste the model ID into `ModelId`. Leave everything else at its default. **Next**.
6. On the options page change nothing. **Next**.
7. At the bottom tick **I acknowledge that AWS CloudFormation might create IAM resources**. **Submit**.
8. Wait for the status `CREATE_COMPLETE`, usually about two minutes. Use the refresh button on the **Events** tab.
9. Open the **Outputs** tab and note the values of `Bucket` and `FunctionName`.

What was created: a private, versioned bucket, a guardrail, a function with placeholder code, a role that can
read that bucket, call the model and write its own logs with everything else denied, and a log group.

## 2. Put the skills and sample data in the bucket

1. Open **S3** and open the bucket named in the `Bucket` output.
2. **Upload**, then **Add folder**. Choose the `skills` folder inside `bucket/`. Repeat **Add folder** for `ownership`
   and for `evidence`. Your browser may ask you to confirm uploading a folder.
3. **Upload**. When it finishes, **Close**.
4. Check the bucket now shows three folders at the top level: `skills/`, `ownership/`, `evidence/`. They must be
   at the top level, not inside a `bucket/` folder.

## 3. Upload the function code

1. Open **Lambda**, then the function named in the `FunctionName` output (`fli-proto-fn`).
2. On the **Code** tab choose **Upload from**, then **.zip file**. Choose `function.zip`. **Save**.
3. Wait for the banner that says the function was updated. The file list on the left should now show
   `handler.py` and folders named `queries` and `config`.

## 4. Try it

1. On the function page open the **Test** tab.
2. **Create new event**. Name it `owned-account`. Replace the Event JSON with the contents of
   `test-events/02-owned-account.json`. **Save**, then **Test**.
3. Expand **Details** on the result. Expect `"status": "ok"`, a `facts` block naming host `APP-BATCH07`, and
   `candidates.allowed` starting with `stale-credential`.
   - With model access: `report` holds a narrative and next steps.
   - Without it: `report` is `null` and `notes` says the summary was withheld. That is the designed fallback.
4. Repeat with the other files:

| Event file | Expect |
|------------|--------|
| `01-list-accounts.json` | `status: ok`, three accounts |
| `03-mandatory-escalation.json` | `must_escalate: true`, only `suspicious-source-escalate` allowed |
| `04-account-not-owned.json` | `status: denied`, `reason: out_of_scope` |
| `05-unknown-caller.json` | `status: denied`, `reason: scope_empty` |
| `06-cloud-sign-in-case.json` | `legacy-auth-client` offered first |

Every result carries a `reference`. Note one for the next step.

## 5. Read the audit trail

1. On the function page open **Monitor**, then **View CloudWatch logs**.
2. Open the newest log stream.
3. In the filter box type `AUDIT`. Each request has one line with the caller, account, outcome and the same
   `reference` you saw in the result. There is no log content and no narrative in it.

## Changing settings later

Change settings through the stack, not on the function, so the next stack update does not undo them.

1. **CloudFormation**, select `fli-proto`, **Update stack**, **Make a direct update**.
2. **Use existing template**, **Next**.
3. Change the parameter, for example `AgentEnabled` to `false` to switch the service off, or `RateLimitPerHour`
   to `30`. **Next**, **Next**, tick the IAM acknowledgement, **Submit**.

Every parameter is described in [`CONFIGURATION.md`](CONFIGURATION.md) under its setting name.

## Turning an evidence source off or on

1. In the stack parameters, set **SourceSwitchKey** to `runtime/switches.json` and update the stack. This is done once.
2. Open the data bucket in the S3 console and create the folder `runtime`.
3. To turn a source off, take a file from `switches/` in the bundle, rename it `switches.json` and upload it into
   `runtime`. `cloud-api-off.json` turns off the sign-in log API and leaves everything else running.
4. Wait one minute, run a test event, and check that the report lists the gap you expect or names the other source.
5. To turn it back on, upload `all-on.json` under the same name, or delete the object.

The switch can only turn off sources the stack already has. Adding or reordering sources is the
**EvidenceSources** parameter, for example `entra_failures=loganalytics+graph`.

## Updating to a newer build

1. Download the newer console bundle.
2. If `template.yaml` changed: **CloudFormation**, select `fli-proto`, **Update stack**, **Make a direct update**,
   **Replace existing template**, upload the new file, keep your parameters, **Submit**. Wait for `UPDATE_COMPLETE`.
3. Upload the new `function.zip` as in step 3. Do this after any template update, because an update can put the
   placeholder code back.
4. Upload the new `skills` folder as in step 2. Uploading over existing objects replaces them. The bucket keeps
   previous versions.

## Removing everything

1. **S3**, select the bucket, **Empty**. Because the bucket is versioned, use **Empty** and not a manual delete,
   so every version is removed. Type the confirmation text and confirm.
2. **CloudFormation**, select `fli-proto`, **Delete**. Wait for the stack to disappear from the list.

Nothing outside the stack was created.

## If something does not match

| What you see | Likely cause | What to do |
|--------------|--------------|------------|
| Stack ends in `ROLLBACK_COMPLETE` | A resource could not be created, often a missing right or a policy that blocks it | Open the **Events** tab, find the first row with status `CREATE_FAILED` and read its reason. Delete the stack before trying again |
| Test returns `"status": "placeholder"` | Step 3 was skipped, or a stack update reset the code | Upload `function.zip` again |
| `ownership_unavailable` on every request | The folders are not at the top level of the bucket | Check step 2, item 4 |
| `unauthenticated` on the test events | `AllowTestClaims` is `false` | The test events only work while it is `true`. Set it back through a stack update |
| `notes` mentions use case details or model not available | The account cannot use that model yet | Have the account owner submit the Anthropic use case details, or choose another model ID through a stack update |
| `notes` says `guardrail_intervened` | The guardrail blocked the request | Expected for hostile input. For ordinary input, open the guardrail in the Bedrock console and review its test tool |
| `Unable to import module 'handler'` | A zip that wraps the files in a folder was uploaded | Use the `function.zip` from the bundle unchanged |
