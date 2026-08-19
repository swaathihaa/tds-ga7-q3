from fastapi import FastAPI, Request

app = FastAPI()

WORKSPACE = "prod-45gh14"

REQUIRED_LABELS = {
    "owner": "student-hx59s",
    "environment": "production",
    "cost_center": "cc-u3r7",
}

VALID_BACKENDS = {
    "gcs",
    "s3",
    "azurerm",
    "remote",
}

VALID_ACTIONS = {
    "create",
    "update",
    "delete",
}

STATEFUL_DELETE_TYPES = {
    "storage_bucket",
    "sql_database",
    "persistent_disk",
}


def reject(reason: str):
    return {
        "decision": "reject",
        "reason": reason,
    }


def approve():
    return {
        "decision": "approve",
        "reason": "APPROVE",
    }


@app.post("/terraform/plan")
async def terraform_plan(request: Request):

    # ==================================================
    # 1. INVALID_PLAN
    # ==================================================

    try:
        body = await request.json()
    except Exception:
        return reject("INVALID_PLAN")

    if not isinstance(body, dict):
        return reject("INVALID_PLAN")

    # All required top-level fields must exist.
    required_top_level = {
        "environment",
        "state",
        "providerVersion",
        "destroyApproved",
        "resource",
    }

    if not required_top_level.issubset(body.keys()):
        return reject("INVALID_PLAN")

    # Top-level types
    if not isinstance(body["environment"], str):
        return reject("INVALID_PLAN")

    if not isinstance(body["state"], dict):
        return reject("INVALID_PLAN")

    if not isinstance(body["providerVersion"], str):
        return reject("INVALID_PLAN")

    if not isinstance(body["destroyApproved"], bool):
        return reject("INVALID_PLAN")

    if not isinstance(body["resource"], dict):
        return reject("INVALID_PLAN")

    state = body["state"]
    resource = body["resource"]

    # State must contain both required fields.
    if not {"backend", "locked"}.issubset(state.keys()):
        return reject("INVALID_PLAN")

    if not isinstance(state["backend"], str):
        return reject("INVALID_PLAN")

    if not isinstance(state["locked"], bool):
        return reject("INVALID_PLAN")

    # Resource must contain every field shown in the schema.
    required_resource = {
        "address",
        "type",
        "action",
        "labels",
        "secret",
        "forceDestroy",
    }

    if not required_resource.issubset(resource.keys()):
        return reject("INVALID_PLAN")

    # Resource field types
    if not isinstance(resource["address"], str):
        return reject("INVALID_PLAN")

    if not isinstance(resource["type"], str):
        return reject("INVALID_PLAN")

    if not isinstance(resource["action"], str):
        return reject("INVALID_PLAN")

    # IMPORTANT:
    # action is explicitly create | update | delete
    if resource["action"] not in VALID_ACTIONS:
        return reject("INVALID_PLAN")

    if not isinstance(resource["labels"], dict):
        return reject("INVALID_PLAN")

    secret = resource["secret"]

    if secret is not None and not isinstance(secret, str):
        return reject("INVALID_PLAN")

    if not isinstance(resource["forceDestroy"], bool):
        return reject("INVALID_PLAN")

    # Label values are strings.
    for key, value in resource["labels"].items():
        if not isinstance(key, str) or not isinstance(value, str):
            return reject("INVALID_PLAN")

    # ==================================================
    # 2. ENVIRONMENT_MISMATCH
    # ==================================================

    if body["environment"] != WORKSPACE:
        return reject("ENVIRONMENT_MISMATCH")

    # ==================================================
    # 3. STATE_UNSAFE
    # ==================================================

    if state["backend"] not in VALID_BACKENDS:
        return reject("STATE_UNSAFE")

    if state["locked"] is not True:
        return reject("STATE_UNSAFE")

    # ==================================================
    # 4. UNPINNED_PROVIDER
    # ==================================================

    provider = body["providerVersion"]

    if provider not in {
        "6.2.1",
        "= 6.2.1",
        "~> 6.0",
    }:
        return reject("UNPINNED_PROVIDER")

    # ==================================================
    # 5. MISSING_LABELS
    # ==================================================

    labels = resource["labels"]

    for key, expected in REQUIRED_LABELS.items():
        if labels.get(key) != expected:
            return reject("MISSING_LABELS")

    # ==================================================
    # 6. PLAINTEXT_SECRET
    # ==================================================

    if secret is not None:
        if secret == "" or not secret.startswith("secret://"):
            return reject("PLAINTEXT_SECRET")

    # ==================================================
    # 7. DELETE_NOT_APPROVED
    # ==================================================

    if (
        resource["action"] == "delete"
        and resource["type"] in STATEFUL_DELETE_TYPES
    ):
        if body["destroyApproved"] is not True:
            return reject("DELETE_NOT_APPROVED")

    # ==================================================
    # 8. FORCE_DESTROY
    # ==================================================

    if (
        body["environment"] == WORKSPACE
        and resource["type"] == "storage_bucket"
        and resource["forceDestroy"] is True
    ):
        return reject("FORCE_DESTROY")

    # ==================================================
    # ALL RULES PASSED
    # ==================================================

    return approve()


@app.get("/")
def root():
    return {
        "service": "Terraform Plan Policy Gate",
        "status": "ok",
    }
