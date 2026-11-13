#!/usr/bin/env bash
# Removes everything the prototype created.
set -euo pipefail
STACK=fli-proto
B=$(aws cloudformation describe-stacks --stack-name "$STACK" --query "Stacks[0].Outputs[?OutputKey=='Bucket'].OutputValue" --output text)
python3 - "$B" <<'PY'
import boto3,sys
boto3.resource("s3").Bucket(sys.argv[1]).object_versions.delete()
PY
aws cloudformation delete-stack --stack-name "$STACK"
aws cloudformation wait stack-delete-complete --stack-name "$STACK"
echo "REMOVED $STACK"
