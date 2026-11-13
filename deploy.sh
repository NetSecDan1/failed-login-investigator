#!/usr/bin/env bash
# Usage: ./deploy.sh <bedrock-model-or-inference-profile-id> [Key=Value template parameters ...]
set -euo pipefail
STACK=fli-proto
MODEL_ID="${1:?pass a Bedrock model or inference profile id}"
cd "$(dirname "$0")"
# Extra template parameters can be passed after the model id, for example:
#   ./deploy.sh <model> JwtIssuer=https://login.microsoftonline.com/<tenant>/v2.0 JwtAudience=api://<app-id> AllowTestClaims=false
shift
aws cloudformation deploy --stack-name "$STACK" --template-file template.yaml \
  --capabilities CAPABILITY_IAM --parameter-overrides "ModelId=$MODEL_ID" "$@" \
  --tags project=fli-proto --no-fail-on-empty-changeset
out() { aws cloudformation describe-stacks --stack-name "$STACK" --query "Stacks[0].Outputs[?OutputKey=='$1'].OutputValue" --output text; }
BUCKET=$(out Bucket); FN=$(out FunctionName)
python3 tools/build_skill_index.py --check
python3 tools/make_data.py
aws s3 sync data/ "s3://$BUCKET/" --delete --exclude "skills/*" --only-show-errors
aws s3 sync skills/ "s3://$BUCKET/skills/" --delete --only-show-errors
rm -f fn.zip; (cd src && zip -qr ../fn.zip . -x '__pycache__/*'); zip -qr fn.zip queries config
aws lambda update-function-code --function-name "$FN" --zip-file fileb://fn.zip --query CodeSha256 --output text
aws lambda wait function-updated --function-name "$FN"
echo "DEPLOYED stack=$STACK fn=$FN bucket=$BUCKET guardrail=$(out GuardrailId)"
