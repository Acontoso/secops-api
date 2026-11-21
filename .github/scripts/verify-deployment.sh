#!/usr/bin/env bash
set -euo pipefail
[[ "${1:-}" == dev || "${1:-}" == prod ]]
environment="$1"
cd "terraform/environments/$environment"
function_name="$(terragrunt run -- output -raw function_name)"
aws lambda wait function-active-v2 --function-name "$function_name"
aws lambda wait function-updated-v2 --function-name "$function_name"
resolved="$(aws lambda get-function --function-name "$function_name" --query 'Code.ResolvedImageUri' --output text)"
[[ "$resolved" == "$TG_ECR_REPOSITORY_URL@$TG_IMAGE_DIGEST" ]]

api="$(terragrunt run -- output -raw api_url)"
pool="$(terragrunt run -- output -raw user_pool_id)"
client="$(terragrunt run -- output -raw client_id)"
scope="$(terragrunt run -- output -raw authorization_scope)"
token_url="$(terragrunt run -- output -raw token_endpoint)"
secret="$(aws cognito-idp describe-user-pool-client --user-pool-id "$pool" --client-id "$client" \
  --query 'UserPoolClient.ClientSecret' --output text)"
echo "::add-mask::$secret"
token="$(curl --proto '=https' --tlsv1.2 --fail --silent --show-error \
  --connect-timeout 5 --max-time 20 --retry 6 --retry-all-errors --retry-delay 5 \
  --user "$client:$secret" --data grant_type=client_credentials --data-urlencode "scope=$scope" \
  "$token_url" | jq -er '.access_token')"
echo "::add-mask::$token"
health="$(mktemp "$RUNNER_TEMP/health.XXXXXX")"
trap 'rm -f "$health"' EXIT
status="$(curl --proto '=https' --tlsv1.2 --fail --silent --show-error \
  --connect-timeout 5 --max-time 20 --retry 6 --retry-all-errors --retry-delay 5 \
  -H "Authorization: Bearer $token" --output "$health" --write-out '%{http_code}' "${api%/}/health")"
[[ "$status" == 200 && "$(<"$health")" == 'API is healthy!' ]]
status="$(curl --proto '=https' --tlsv1.2 --silent --show-error --connect-timeout 5 --max-time 20 \
  --output /dev/null --write-out '%{http_code}' "${api%/}/health")"
[[ "$status" == 401 || "$status" == 403 ]]
printf '## %s verified\n\nCommit: `%s`\n\nImage: `%s`\n\nRelease: `%s`\n\nHealth and anonymous rejection passed.\n' \
  "$environment" "$GITHUB_SHA" "$TG_IMAGE_DIGEST" "${RELEASE_VERSION:-not yet versioned}" >> "$GITHUB_STEP_SUMMARY"
