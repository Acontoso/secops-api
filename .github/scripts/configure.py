"""Map GitHub variables to the existing Terragrunt interface; never print values."""
import json
import os
import re
from pathlib import Path


def configure(variables, environment):
    if environment not in ("dev", "prod"):
        raise ValueError("environment must be dev or prod")
    prefix = environment.upper() + "_"
    required = ("AWS_ACCOUNT_ID", "AWS_REGION", "STATE_BUCKET", "SSM_KMS_KEY_ARN",
                "APPLICATION_KMS_KEY_ARN", "IDENTITY_POOL_ID", "IDENTITY_POOL_LOGIN", "ROLE_ARN")
    missing = [prefix + key for key in required if not variables.get(prefix + key)]
    missing += [key for key in ("ECR_REPOSITORY_URL", "ECR_ACCOUNT_ID", "ECR_REGION")
                if not variables.get(key)]
    if missing:
        raise ValueError("Missing GitHub variables: " + ", ".join(missing))
    account, region = variables[prefix + "AWS_ACCOUNT_ID"], variables[prefix + "AWS_REGION"]
    if not re.fullmatch(r"[0-9]{12}", account):
        raise ValueError(prefix + "AWS_ACCOUNT_ID must be 12 digits")
    ecr_account, ecr_region = variables["ECR_ACCOUNT_ID"], variables["ECR_REGION"]
    expected = rf"{re.escape(ecr_account)}\.dkr\.ecr\.{re.escape(ecr_region)}\.amazonaws\.com(?:\.cn)?/[a-z0-9][a-z0-9._/-]*"
    if not re.fullmatch(r"[0-9]{12}", ecr_account) or not re.fullmatch(expected, variables["ECR_REPOSITORY_URL"]):
        raise ValueError("Shared ECR URL does not match ECR_ACCOUNT_ID/ECR_REGION")
    if region != ecr_region:
        raise ValueError("Lambda and shared ECR must use the same region")
    if not re.fullmatch(rf"arn:[a-z-]+:iam::{account}:role/[A-Za-z0-9+=,.@_/-]+", variables[prefix + "ROLE_ARN"]):
        raise ValueError(prefix + "ROLE_ARN must belong to the environment account")
    result = {"TG_" + key: variables[prefix + key] for key in required if key not in ("ROLE_ARN", "AWS_ACCOUNT_ID")}
    result.update(TG_ACCOUNT_ID=account, ROLE_ARN=variables[prefix + "ROLE_ARN"],
                  TG_STATE_REGION=variables.get(prefix + "STATE_REGION") or region,
                  TG_ECR_REPOSITORY_URL=variables["ECR_REPOSITORY_URL"])
    for key in ("ECR_REPOSITORY_URL", "ECR_ACCOUNT_ID", "ECR_REGION"):
        result[key] = variables[key]
    for key, default in (("INTEGRATION_ENVIRONMENT", {}), ("AGENTCORE", None), ("NOTIFICATION_SUBSCRIPTIONS", {})):
        value = json.loads(variables.get(prefix + key) or json.dumps(default))
        expected_type = dict if key != "AGENTCORE" else (dict, type(None))
        if not isinstance(value, expected_type):
            raise ValueError(prefix + key + " has the wrong JSON type")
        result["TG_" + key] = json.dumps(value, separators=(",", ":"))
    result["TG_API_CLOUDWATCH_ROLE_ARN"] = variables.get(prefix + "API_CLOUDWATCH_ROLE_ARN", "")
    if any("\n" in value or "\r" in value for value in result.values()):
        raise ValueError("Configuration must not contain newline characters")
    return result


if __name__ == "__main__":
    try:
        values = configure(json.loads(os.environ["VARS_JSON"]), os.environ["DEPLOY_ENV"])
        with Path(os.environ["GITHUB_ENV"]).open("a") as output:
            for key, value in values.items():
                output.write(f"{key}={value}\n")
    except (ValueError, KeyError) as error:
        raise SystemExit(f"::error::{error}") from error
