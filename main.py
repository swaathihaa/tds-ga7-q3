from typing import Any

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

    # --------------------------------------------------
    # 1. REQUEST / NESTED OBJECT TYPES
    # --------------------------------------------------

    try:
        body = await request.json()
    except Exception:
        return reject("INVALID_PLAN")

    if not isinstance(body, dict):
        return reject("INVALID_PLAN")

    # Required top-level fields and types
    if not isinstance(body.get("environment"), str):
        return reject("INVALID_PLAN")

    if not isinstance(body.get("state"), dict):
        return reject("INVALID_PLAN")

    if not isinstance(body.get("providerVersion"), str):
        return reject("INVALID_PLAN")

    if not isinstance(body.get("destroyApproved"), bool):
        return reject("INVALID_PLAN")

    if not isinstance(body.get("resource"), dict):
        return reject("INVALID_PLAN")

    state = body["state"]
    resource = body["resource"]

    # State nested types
    if not isinstance(state.get("backend"), str):
        return reject("INVALID_PLAN")

    if not isinstance(state.get("locked"), bool):
        return reject("INVALID_PLAN")

    # Resource nested types
    if not isinstance(resource.get("address"), str):
        return reject("INVALID_PLAN")

    if not isinstance(resource.get("type"), str):
        return reject("INVALID_PLAN")

    if not isinstance(resource.get("action"), str):
        return reject("INVALID_PLAN")

    if not isinstance(resource.get("labels"), dict):
        return reject("INVALID_PLAN")

    # secret must be null or string
    secret = resource.get("secret")

    if secret is not None and not isinstance(secret, str):
        return reject("INVALID_PLAN")

    # forceDestroy must be boolean
    if not isinstance(resource.get("forceDestroy"), bool):
        return reject("INVALID_PLAN")

    # --------------------------------------------------
    # 2. ENVIRONMENT
    # --------------------------------------------------

    if body["environment"] != WORKSPACE:
        return reject("ENVIRONMENT_MISMATCH")

    # --------------------------------------------------
    # 3. STATE
    # --------------------------------------------------

    if state["backend"] not in VALID_BACKENDS:
        return reject("STATE_UNSAFE")

    if state["locked"] is not True:
        return reject("STATE_UNSAFE")

    # --------------------------------------------------
    # 4. PROVIDER VERSION
    # --------------------------------------------------

    provider = body["providerVersion"]

    if provider not in {
        "6.2.1",
        "= 6.2.1",
        "~> 6.0",
    }:
        return reject("UNPINNED_PROVIDER")

    # --------------------------------------------------
    # 5. REQUIRED LABELS
    # --------------------------------------------------

    labels = resource["labels"]

    for key, expected in REQUIRED_LABELS.items():
        if labels.get(key) != expected:
            return reject("MISSING_LABELS")

    # --------------------------------------------------
    # 6. SECRET
    # --------------------------------------------------

    if secret is not None:
        if secret == "" or not secret.startswith("secret://"):
            return reject("PLAINTEXT_SECRET")

    # --------------------------------------------------
    # 7. DESTRUCTIVE DELETE
    # --------------------------------------------------

    if (
        resource["action"] == "delete"
        and resource["type"] in STATEFUL_DELETE_TYPES
    ):
        if body["destroyApproved"] is not True:
            return reject("DELETE_NOT_APPROVED")

    # --------------------------------------------------
    # 8. FORCE DESTROY
    # --------------------------------------------------

    if (
        body["environment"] == WORKSPACE
        and resource["type"] == "storage_bucket"
        and resource["forceDestroy"] is True
    ):
        return reject("FORCE_DESTROY")

    # --------------------------------------------------
    # EVERYTHING PASSED
    # --------------------------------------------------

    return approve()


@app.get("/")
def root():
    return {
        "service": "Terraform Plan Policy Gate",
        "status": "ok",
    }
