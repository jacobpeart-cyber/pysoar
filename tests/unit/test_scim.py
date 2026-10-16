"""SCIM 2.0 provisioning: tokens, authentication, Users, Groups (role mappings),
discovery documents and audit rows. The requests are the shapes Okta and
Microsoft Entra ID send."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from sqlalchemy import select

from src.identity.models import Role, SCIMToken, SSOConfiguration
from src.identity.scim import SCHEMA_ENTERPRISE, SCHEMA_ERROR, SCHEMA_GROUP, SCHEMA_LIST, SCHEMA_PATCH, SCHEMA_USER
from src.models.audit import AuditLog
from src.models.user import User
from tests.helpers.tenancy import bearer, make_user
from tests.unit.test_token_revocation import _stateful

BASE = "/api/v1/scim/v2"


async def issue_token(client, headers, name: str = "okta", **body: Any) -> str:
    r = await client.post("/api/v1/settings/scim/tokens", json={"name": name, **body}, headers=headers)
    assert r.status_code == 201, r.text
    return r.json()["token"]


def scim_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/scim+json"}


async def fresh(db, model, obj_id):
    return (
        await db.execute(select(model).where(model.id == obj_id).execution_options(populate_existing=True))
    ).scalar_one()


async def audit_actions(db, org_id: str) -> list[str]:
    rows = (await db.execute(
        select(AuditLog.action).where(AuditLog.organization_id == org_id).execution_options(populate_existing=True)
    )).scalars().all()
    return list(rows)


def new_user_body(email: str, **extra: Any) -> dict[str, Any]:
    return {
        "schemas": [SCHEMA_USER],
        "userName": email,
        "name": {"givenName": "Ada", "familyName": "Lovelace"},
        "emails": [{"value": email, "type": "work", "primary": True}],
        "active": True,
        **extra,
    }


def email() -> str:
    return f"scim-{uuid.uuid4().hex[:8]}@pysoar-tests.io"


async def create_scim_user(client, token: str, addr: str | None = None, **extra: Any) -> dict[str, Any]:
    r = await client.post(f"{BASE}/Users", json=new_user_body(addr or email(), **extra), headers=scim_headers(token))
    assert r.status_code == 201, r.text
    return r.json()


# ---------------------------------------------------------------------------
# Tokens and authentication
# ---------------------------------------------------------------------------


async def test_token_issue_list_revoke(client, db_session, org_a, org_a_admin_headers) -> None:
    org_id = org_a.id
    r = await client.post("/api/v1/settings/scim/tokens", json={"name": "okta", "expires_in_days": 30},
                          headers=org_a_admin_headers)
    assert r.status_code == 201, r.text
    body = r.json()
    token = body["token"]
    assert token.startswith("scim_") and body["token_prefix"] == token[:12] and body["status"] == "active"
    assert body["scim_base_url"].endswith("/api/v1/scim/v2") and body["expires_at"]
    stored = await fresh(db_session, SCIMToken, body["id"])
    assert stored.token_hash != token and len(stored.token_hash) == 64

    listing = (await client.get("/api/v1/settings/scim/tokens", headers=org_a_admin_headers)).json()
    assert [t["id"] for t in listing["items"]] == [body["id"]]
    assert "token" not in listing["items"][0] and token not in str(listing)

    assert (await client.get(f"{BASE}/Users", headers=scim_headers(token))).status_code == 200
    stored = await fresh(db_session, SCIMToken, body["id"])
    assert stored.last_used_at is not None

    r = await client.delete(f"/api/v1/settings/scim/tokens/{body['id']}", headers=org_a_admin_headers)
    assert r.status_code == 204
    r = await client.get(f"{BASE}/Users", headers=scim_headers(token))
    assert r.status_code == 401 and r.json()["detail"] == "SCIM token revoked"
    listing = (await client.get("/api/v1/settings/scim/tokens", headers=org_a_admin_headers)).json()
    assert listing["items"][0]["status"] == "revoked"
    # Revoking twice is a no-op, not a second audit row.
    assert (await client.delete(f"/api/v1/settings/scim/tokens/{body['id']}", headers=org_a_admin_headers)).status_code == 204
    actions = await audit_actions(db_session, org_id)
    assert actions.count("scim_token_created") == 1 and actions.count("scim_token_revoked") == 1


async def test_expired_token_is_refused(client, db_session, org_a, org_a_admin_headers) -> None:
    token = await issue_token(client, org_a_admin_headers, expires_in_days=1)
    row = (await db_session.execute(select(SCIMToken))).scalar_one()
    row.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
    await db_session.commit()
    r = await client.get(f"{BASE}/Users", headers=scim_headers(token))
    assert r.status_code == 401 and r.json()["detail"] == "SCIM token expired"


@pytest.mark.parametrize("header", [None, "Bearer scim_not-a-real-token", "Basic dXNlcjpwYXNz", "Bearer "])
async def test_auth_failures_answer_scim_errors(client, header) -> None:
    headers = {"Authorization": header} if header else {}
    r = await client.get(f"{BASE}/Users", headers=headers)
    assert r.status_code == 401
    body = r.json()
    assert body["schemas"] == [SCHEMA_ERROR] and body["status"] == "401"
    assert r.headers["content-type"].startswith("application/scim+json")
    assert "bearer" in r.headers["www-authenticate"].lower()


async def test_a_user_jwt_is_not_a_scim_token(client, org_a_admin, org_a_admin_headers) -> None:
    r = await client.get(f"{BASE}/Users", headers=org_a_admin_headers)
    assert r.status_code == 401 and r.json()["schemas"] == [SCHEMA_ERROR]


async def test_token_admin_routes_need_admin(client, org_a, org_a_headers, viewer_headers) -> None:
    for headers in (org_a_headers, viewer_headers):
        for method, path, body in (
            ("get", "/api/v1/settings/scim/tokens", None),
            ("post", "/api/v1/settings/scim/tokens", {"name": "x"}),
            ("delete", f"/api/v1/settings/scim/tokens/{uuid.uuid4()}", None),
            ("get", "/api/v1/settings/scim/groups", None),
            ("put", f"/api/v1/settings/scim/groups/{uuid.uuid4()}", {"role": "admin"}),
        ):
            r = await client.request(method.upper(), path, json=body, headers=headers)
            assert r.status_code == 403, (method, path, r.text)


async def test_orgless_superuser_gets_organization_required(client, superuser_headers) -> None:
    for method, path, body in (
        ("get", "/api/v1/settings/scim/tokens", None),
        ("post", "/api/v1/settings/scim/tokens", {"name": "x"}),
        ("get", "/api/v1/settings/scim/groups", None),
    ):
        r = await client.request(method.upper(), path, json=body, headers=superuser_headers)
        assert r.status_code == 403 and r.json()["detail"]["error"] == "organization_required"


async def test_custom_role_admin_cannot_mint_a_token(client, db_session, org_a) -> None:
    org_id = org_a.id
    role = Role(organization_id=org_id, name="settings-admin", default_tier="admin", area_tiers={})
    db_session.add(role)
    await db_session.commit()
    holder = await make_user(db_session, role="viewer", organization_id=org_id, label="custom-admin")
    holder.custom_role_id = role.id
    await db_session.commit()
    headers = bearer(holder)
    assert (await client.get("/api/v1/settings/scim/tokens", headers=headers)).status_code == 200
    r = await client.post("/api/v1/settings/scim/tokens", json={"name": "x"}, headers=headers)
    assert r.status_code == 403 and r.json()["detail"]["error"] == "full_admin_required"


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


def _declared(schema_doc: dict[str, Any]) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for attr in schema_doc["attributes"]:
        out[attr["name"]] = {s["name"] for s in attr.get("subAttributes", [])}
    return out


async def test_discovery_documents(client, org_a_admin_headers) -> None:
    token = await issue_token(client, org_a_admin_headers)
    h = scim_headers(token)
    spc = (await client.get(f"{BASE}/ServiceProviderConfig", headers=h)).json()
    assert spc["patch"]["supported"] is True and spc["bulk"]["supported"] is False
    assert spc["filter"] == {"supported": True, "maxResults": 200}
    assert spc["changePassword"]["supported"] is False and spc["authenticationSchemes"][0]["type"] == "oauthbearertoken"
    rts = (await client.get(f"{BASE}/ResourceTypes", headers=h)).json()
    assert rts["schemas"] == [SCHEMA_LIST] and {r["id"] for r in rts["Resources"]} == {"User", "Group"}
    assert (await client.get(f"{BASE}/ResourceTypes/User", headers=h)).json()["endpoint"] == "/Users"
    assert (await client.get(f"{BASE}/ResourceTypes/Nope", headers=h)).status_code == 404
    schemas = (await client.get(f"{BASE}/Schemas", headers=h)).json()
    ids = {s["id"] for s in schemas["Resources"]}
    assert ids == {SCHEMA_USER, SCHEMA_GROUP, SCHEMA_ENTERPRISE}
    one = (await client.get(f"{BASE}/Schemas/{SCHEMA_USER}", headers=h)).json()
    for attr in one["attributes"]:
        for key in ("name", "type", "multiValued", "required", "mutability", "returned", "uniqueness"):
            assert key in attr


async def test_emitted_resources_match_the_declared_schemas(client, db_session, org_a, org_a_admin_headers) -> None:
    token = await issue_token(client, org_a_admin_headers)
    h = scim_headers(token)
    user = await create_scim_user(
        client, token, externalId="ext-1", phoneNumbers=[{"value": "+1 555 0100", "type": "work"}],
        **{SCHEMA_ENTERPRISE: {"department": "SOC"}},
    )
    group = (await client.post(f"{BASE}/Groups", json={"schemas": [SCHEMA_GROUP], "displayName": "Analysts",
                                                        "members": [{"value": user["id"]}]}, headers=h)).json()
    user = (await client.get(f"{BASE}/Users/{user['id']}", headers=h)).json()
    docs = {s["id"]: _declared(s) for s in (await client.get(f"{BASE}/Schemas", headers=h)).json()["Resources"]}
    common = {"schemas", "id", "externalId", "meta"}
    for resource, schema_id in ((user, SCHEMA_USER), (group, SCHEMA_GROUP)):
        declared = docs[schema_id]
        for key, value in resource.items():
            if key in common:
                continue
            if key == SCHEMA_ENTERPRISE:
                assert set(value) <= set(docs[SCHEMA_ENTERPRISE])
                continue
            assert key in declared, f"{schema_id} does not declare {key}"
            items = value if isinstance(value, list) else [value]
            for item in items:
                if isinstance(item, dict):
                    assert set(item) <= declared[key], (key, set(item) - declared[key])
    assert user["groups"][0]["value"] == group["id"] and user[SCHEMA_ENTERPRISE] == {"department": "SOC"}
    assert user["meta"]["resourceType"] == "User" and user["meta"]["location"].endswith(f"/Users/{user['id']}")
    assert group["meta"]["resourceType"] == "Group"


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------


async def test_create_user(client, db_session, org_a, org_a_admin_headers) -> None:
    org_id = org_a.id
    token = await issue_token(client, org_a_admin_headers)
    addr = email()
    r = await client.post(f"{BASE}/Users", json=new_user_body(addr.upper(), externalId="00u1", password="ignored-pw-1"),
                          headers=scim_headers(token))
    assert r.status_code == 201, r.text
    body = r.json()
    assert r.headers["location"] == body["meta"]["location"]
    assert body["userName"] == addr and body["active"] is True and body["externalId"] == "00u1"
    assert body["name"]["givenName"] == "Ada" and body["name"]["familyName"] == "Lovelace"
    user = await fresh(db_session, User, body["id"])
    assert user.organization_id == org_id and user.identity_source == "scim" and user.role == "viewer"
    assert user.full_name == "Ada Lovelace" and not user.is_superuser
    from src.core.security import verify_password
    assert not verify_password("ignored-pw-1", user.hashed_password)
    assert "scim_user_created" in await audit_actions(db_session, org_id)
    # Password sign-in is not available to a SCIM-provisioned user.
    r = await client.post("/api/v1/auth/login", json={"email": addr, "password": "ignored-pw-1"})
    assert r.status_code == 401


async def test_create_user_uniqueness(client, db_session, org_a, org_b, org_a_admin_headers) -> None:
    other = await make_user(db_session, role="analyst", organization_id=org_b.id, label="taken")
    other_email = other.email
    token = await issue_token(client, org_a_admin_headers)
    addr = email()
    await create_scim_user(client, token, addr)
    for clash in (addr, addr.upper(), other_email):
        r = await client.post(f"{BASE}/Users", json=new_user_body(clash), headers=scim_headers(token))
        assert r.status_code == 409, clash
        assert r.json()["scimType"] == "uniqueness" and r.json()["schemas"] == [SCHEMA_ERROR]


@pytest.mark.parametrize("body", [
    {"userName": "not-an-email"},
    {"name": {"givenName": "x"}},
    {"userName": "a@b.io", "active": "maybe"},
])
async def test_create_user_invalid(client, org_a_admin_headers, body) -> None:
    token = await issue_token(client, org_a_admin_headers)
    r = await client.post(f"{BASE}/Users", json={"schemas": [SCHEMA_USER], **body}, headers=scim_headers(token))
    assert r.status_code == 400 and r.json()["scimType"] == "invalidValue"


async def test_invalid_json_is_invalid_syntax(client, org_a_admin_headers) -> None:
    token = await issue_token(client, org_a_admin_headers)
    r = await client.post(f"{BASE}/Users", content=b"{not json", headers=scim_headers(token))
    assert r.status_code == 400 and r.json()["scimType"] == "invalidSyntax"


async def test_default_role_comes_from_the_sso_configuration(client, db_session, org_a, org_a_admin_headers) -> None:
    org_id = org_a.id
    role = Role(organization_id=org_id, name="tier1", default_tier="read", area_tiers={"alerts": "write"})
    db_session.add(role)
    await db_session.flush()
    db_session.add(SSOConfiguration(organization_id=org_id, issuer="https://idp.example", client_id="c",
                                    default_role="analyst", group_role_map={}))
    await db_session.commit()
    role_id = role.id
    token = await issue_token(client, org_a_admin_headers)
    user = await fresh(db_session, User, (await create_scim_user(client, token))["id"])
    assert user.role == "analyst" and user.custom_role_id is None
    config = (await db_session.execute(select(SSOConfiguration))).scalar_one()
    config.default_role = "tier1"
    await db_session.commit()
    user = await fresh(db_session, User, (await create_scim_user(client, token))["id"])
    assert user.custom_role_id == role_id and user.role == "viewer"


async def test_list_filter_and_paging(client, db_session, org_a, org_a_admin_headers) -> None:
    org_id = org_a.id
    su = await make_user(db_session, role="admin", organization_id=org_id, is_superuser=True, label="su-in-org")
    su_id = su.id
    token = await issue_token(client, org_a_admin_headers)
    h = scim_headers(token)
    made = [await create_scim_user(client, token, externalId=f"ext-{i}") for i in range(3)]
    listing = (await client.get(f"{BASE}/Users", headers=h)).json()
    assert listing["schemas"] == [SCHEMA_LIST]
    ids = [r["id"] for r in listing["Resources"]]
    # The fixture admin plus the three SCIM users; never the superuser.
    assert listing["totalResults"] == 4 and su_id not in ids and all(m["id"] in ids for m in made)

    target = made[1]
    for flt in (
        f'userName eq "{target["userName"].upper()}"',
        'externalId eq "ext-1"',
        f'emails.value eq "{target["userName"]}"',
        f'USERNAME EQ "{target["userName"]}"',
    ):
        found = (await client.get(f"{BASE}/Users", params={"filter": flt}, headers=h)).json()
        assert found["totalResults"] == 1 and found["Resources"][0]["id"] == target["id"], flt
    none = (await client.get(f"{BASE}/Users", params={"filter": 'userName eq "nobody@x.io"'}, headers=h)).json()
    assert none["totalResults"] == 0 and none["Resources"] == []

    page = (await client.get(f"{BASE}/Users", params={"startIndex": 2, "count": 2}, headers=h)).json()
    assert page["startIndex"] == 2 and page["itemsPerPage"] == 2 and page["totalResults"] == 4
    assert [r["id"] for r in page["Resources"]] == ids[1:3]
    zero = (await client.get(f"{BASE}/Users", params={"count": 0}, headers=h)).json()
    assert zero["totalResults"] == 4 and zero["Resources"] == []
    capped = (await client.get(f"{BASE}/Users", params={"count": 5000, "startIndex": 0}, headers=h)).json()
    assert capped["startIndex"] == 1 and capped["itemsPerPage"] == 4
    projected = (await client.get(f"{BASE}/Users", params={"attributes": "userName"}, headers=h)).json()
    assert set(projected["Resources"][0]) == {"schemas", "id", "meta", "userName"}

    for bad in ('title eq "x"', 'userName co "a"', 'userName eq "a" and active eq true'):
        r = await client.get(f"{BASE}/Users", params={"filter": bad}, headers=h)
        assert r.status_code == 400 and r.json()["scimType"] == "invalidFilter", bad
    r = await client.get(f"{BASE}/Users/{su_id}", headers=h)
    assert r.status_code == 404


async def test_put_replaces_the_user(client, db_session, org_a, org_a_admin_headers) -> None:
    token = await issue_token(client, org_a_admin_headers)
    h = scim_headers(token)
    created = await create_scim_user(client, token, externalId="old")
    taken = await create_scim_user(client, token)
    new_email = email()
    body = {"schemas": [SCHEMA_USER], "userName": new_email, "name": {"givenName": "Grace", "familyName": "Hopper"},
            "active": True}
    r = await client.put(f"{BASE}/Users/{created['id']}", json=body, headers=h)
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["userName"] == new_email and out["name"]["formatted"] == "Grace Hopper" and "externalId" not in out
    r = await client.put(f"{BASE}/Users/{created['id']}", json={**body, "userName": taken["userName"]}, headers=h)
    assert r.status_code == 409 and r.json()["scimType"] == "uniqueness"


async def test_okta_patch_deactivates_and_revokes_tokens(
    client, db_session, org_a, org_a_admin_headers, redis_mock,
) -> None:
    store = _stateful(redis_mock)
    org_id = org_a.id
    token = await issue_token(client, org_a_admin_headers)
    victim = await make_user(db_session, role="analyst", organization_id=org_id, label="victim")
    victim.identity_source = "scim"
    await db_session.commit()
    victim_id = victim.id
    victim_headers = bearer(victim)
    assert (await client.get("/api/v1/auth/me", headers=victim_headers)).status_code == 200

    okta = {"schemas": [SCHEMA_PATCH], "Operations": [{"op": "replace", "value": {"active": False}}]}
    r = await client.patch(f"{BASE}/Users/{victim_id}", json=okta, headers=scim_headers(token))
    assert r.status_code == 200 and r.json()["active"] is False
    assert store.get(f"revoke_gen:{victim_id}") == "1"
    assert (await client.get("/api/v1/auth/me", headers=victim_headers)).status_code in (401, 403)
    actions = await audit_actions(db_session, org_id)
    assert "scim_user_deactivated" in actions

    okta["Operations"][0]["value"]["active"] = True
    r = await client.patch(f"{BASE}/Users/{victim_id}", json=okta, headers=scim_headers(token))
    assert r.status_code == 200 and r.json()["active"] is True
    assert (await fresh(db_session, User, victim_id)).is_active is True
    assert "scim_user_reactivated" in await audit_actions(db_session, org_id)


async def test_entra_patch_operations(client, db_session, org_a, org_a_admin_headers, redis_mock) -> None:
    store = _stateful(redis_mock)
    org_id = org_a.id
    token = await issue_token(client, org_a_admin_headers)
    created = await create_scim_user(client, token)
    uid = created["id"]
    entra = {
        "schemas": [SCHEMA_PATCH],
        "Operations": [
            {"op": "Replace", "path": "name.givenName", "value": "Katherine"},
            {"op": "Replace", "path": "name.familyName", "value": "Johnson"},
            {"op": "Add", "path": "externalId", "value": "aad-object-id"},
            {"op": "Replace", "path": 'phoneNumbers[type eq "work"].value', "value": "+1 555 0101"},
            {"op": "Add", "path": f"{SCHEMA_ENTERPRISE}:department", "value": "Detection"},
            {"op": "Add", "path": "title", "value": "Engineer"},
            {"op": "Replace", "path": 'emails[type eq "work"].value', "value": created["userName"]},
            {"op": "Replace", "path": "active", "value": "False"},
        ],
    }
    r = await client.patch(f"{BASE}/Users/{uid}", json=entra, headers=scim_headers(token))
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["name"]["formatted"] == "Katherine Johnson" and out["externalId"] == "aad-object-id"
    assert out["phoneNumbers"][0]["value"] == "+1 555 0101" and out[SCHEMA_ENTERPRISE]["department"] == "Detection"
    assert out["active"] is False and store.get(f"revoke_gen:{uid}") == "1"
    row = (await db_session.execute(
        select(AuditLog).where(AuditLog.action == "scim_user_updated", AuditLog.resource_id == uid)
        .execution_options(populate_existing=True)
    )).scalars().all()[-1]
    assert '"ignored_attributes": ["title"]' in row.new_value and "scim_token:" in row.new_value
    assert org_id == row.organization_id

    remove = {"schemas": [SCHEMA_PATCH], "Operations": [{"op": "remove", "path": "externalId"}]}
    out = (await client.patch(f"{BASE}/Users/{uid}", json=remove, headers=scim_headers(token))).json()
    assert "externalId" not in out


@pytest.mark.parametrize("ops", [
    [{"op": "move", "path": "active", "value": False}],
    [],
    [{"op": "remove"}],
    [{"op": "remove", "path": "userName"}],
])
async def test_bad_patch_is_refused(client, org_a_admin_headers, ops) -> None:
    token = await issue_token(client, org_a_admin_headers)
    created = await create_scim_user(client, token)
    r = await client.patch(f"{BASE}/Users/{created['id']}", json={"schemas": [SCHEMA_PATCH], "Operations": ops},
                           headers=scim_headers(token))
    assert r.status_code == 400 and r.json()["schemas"] == [SCHEMA_ERROR]


async def test_delete_deactivates_never_deletes(client, db_session, org_a, org_a_admin_headers, redis_mock) -> None:
    store = _stateful(redis_mock)
    token = await issue_token(client, org_a_admin_headers)
    created = await create_scim_user(client, token)
    uid = created["id"]
    r = await client.delete(f"{BASE}/Users/{uid}", headers=scim_headers(token))
    assert r.status_code == 204
    user = await fresh(db_session, User, uid)
    assert user.is_active is False and store.get(f"revoke_gen:{uid}") == "1"
    got = (await client.get(f"{BASE}/Users/{uid}", headers=scim_headers(token))).json()
    assert got["active"] is False
    # A second DELETE changes nothing (no second revocation).
    assert (await client.delete(f"{BASE}/Users/{uid}", headers=scim_headers(token))).status_code == 204
    assert store.get(f"revoke_gen:{uid}") == "1"
    assert (await client.delete(f"{BASE}/Users/{uuid.uuid4()}", headers=scim_headers(token))).status_code == 404


# ---------------------------------------------------------------------------
# Groups
# ---------------------------------------------------------------------------


async def _group(client, token, name: str, members: list[str] | None = None) -> dict[str, Any]:
    r = await client.post(f"{BASE}/Groups", json={"schemas": [SCHEMA_GROUP], "displayName": name,
                                                   "members": [{"value": m} for m in members or []]},
                          headers=scim_headers(token))
    assert r.status_code == 201, r.text
    return r.json()


def _members_patch(op: str, ids: list[str]) -> dict[str, Any]:
    return {"schemas": [SCHEMA_PATCH], "Operations": [{"op": op, "path": "members", "value": [{"value": i} for i in ids]}]}


async def test_group_mapping_assigns_and_clears_roles(client, db_session, org_a, org_a_admin_headers) -> None:
    org_id = org_a.id
    token = await issue_token(client, org_a_admin_headers)
    h = scim_headers(token)
    u1 = (await create_scim_user(client, token))["id"]
    u2 = (await create_scim_user(client, token))["id"]
    group = await _group(client, token, "PySOAR Analysts")
    gid = group["id"]
    assert group["members"] == []

    # Unmapped group: membership changes no role.
    r = await client.patch(f"{BASE}/Groups/{gid}", json=_members_patch("add", [u1]), headers=h)
    assert r.status_code == 200 and [m["value"] for m in r.json()["members"]] == [u1]
    assert (await fresh(db_session, User, u1)).role == "viewer"

    # Mapping the group (no SSO configuration: kept in the group record) applies at once.
    r = await client.put(f"/api/v1/settings/scim/groups/{gid}", json={"role": "analyst"}, headers=org_a_admin_headers)
    assert r.status_code == 200, r.text
    assert r.json()["role"] == "analyst" and r.json()["mapping_source"] == "scim_groups" and r.json()["member_count"] == 1
    assert (await fresh(db_session, User, u1)).role == "analyst"

    r = await client.patch(f"{BASE}/Groups/{gid}", json=_members_patch("add", [u2]), headers=h)
    assert r.status_code == 200 and (await fresh(db_session, User, u2)).role == "analyst"
    user_view = (await client.get(f"{BASE}/Users/{u2}", headers=h)).json()
    assert user_view["groups"] == [{"value": gid, "display": "PySOAR Analysts", "$ref": user_view["groups"][0]["$ref"]}]

    # Okta removes a member with a value-filter path; the member falls back to the default role.
    okta_remove = {"schemas": [SCHEMA_PATCH], "Operations": [{"op": "remove", "path": f'members[value eq "{u1}"]'}]}
    r = await client.patch(f"{BASE}/Groups/{gid}", json=okta_remove, headers=h)
    assert r.status_code == 200 and [m["value"] for m in r.json()["members"]] == [u2]
    assert (await fresh(db_session, User, u1)).role == "viewer"

    # Custom role mapping goes through apply_custom_role (built-in floored to viewer).
    role = Role(organization_id=org_id, name="hunters", default_tier="read", area_tiers={"hunting": "write"})
    db_session.add(role)
    await db_session.commit()
    role_id = role.id
    hunters = await _group(client, token, "Hunters", [u1])
    r = await client.put(f"/api/v1/settings/scim/groups/{hunters['id']}", json={"role": "hunters"},
                         headers=org_a_admin_headers)
    assert r.status_code == 200 and r.json()["role"] == role_id
    user = await fresh(db_session, User, u1)
    assert user.custom_role_id == role_id and user.role == "viewer"
    # In both groups: analyst (built-in) outranks the custom role.
    await client.patch(f"{BASE}/Groups/{gid}", json=_members_patch("add", [u1]), headers=h)
    user = await fresh(db_session, User, u1)
    assert user.role == "analyst" and user.custom_role_id is None

    # Deleting the analysts group recomputes its members from what is left.
    assert (await client.delete(f"{BASE}/Groups/{gid}", headers=h)).status_code == 204
    assert (await fresh(db_session, User, u1)).custom_role_id == role_id
    assert (await fresh(db_session, User, u2)).role == "viewer"
    assert (await client.get(f"{BASE}/Groups/{gid}", headers=h)).status_code == 404

    actions = await audit_actions(db_session, org_id)
    for action in ("scim_group_created", "scim_group_updated", "scim_group_deleted", "scim_role_assigned",
                   "scim_group_mapping_updated"):
        assert action in actions, action

    r = await client.put(f"/api/v1/settings/scim/groups/{hunters['id']}", json={"role": "no-such-role"},
                         headers=org_a_admin_headers)
    assert r.status_code == 422 and r.json()["detail"]["error"] == "unknown_role"
    listing = (await client.get("/api/v1/settings/scim/groups", headers=org_a_admin_headers)).json()
    assert [g["display_name"] for g in listing["items"]] == ["Hunters"]


async def test_sso_group_role_map_drives_groups(client, db_session, org_a, org_a_admin_headers) -> None:
    org_id = org_a.id
    db_session.add(SSOConfiguration(organization_id=org_id, issuer="https://idp.example", client_id="c",
                                    default_role="viewer", group_role_map={"SOC Admins": "admin"}))
    await db_session.commit()
    token = await issue_token(client, org_a_admin_headers)
    h = scim_headers(token)
    uid = (await create_scim_user(client, token))["id"]
    group = await _group(client, token, "SOC Admins", [uid])
    assert (await fresh(db_session, User, uid)).role == "admin"

    # Entra renames the group: the SSO mapping key follows.
    rename = {"schemas": [SCHEMA_PATCH], "Operations": [{"op": "Replace", "path": "displayName", "value": "SOC Leads"}]}
    r = await client.patch(f"{BASE}/Groups/{group['id']}", json=rename, headers=h)
    assert r.status_code == 200 and r.json()["displayName"] == "SOC Leads"
    config = (await db_session.execute(select(SSOConfiguration).execution_options(populate_existing=True))).scalar_one()
    assert config.group_role_map == {"SOC Leads": "admin"}
    assert (await fresh(db_session, User, uid)).role == "admin"

    # Admin unmaps through the settings route: written to the SSO map; member falls back to default.
    r = await client.put(f"/api/v1/settings/scim/groups/{group['id']}", json={"role": None}, headers=org_a_admin_headers)
    assert r.status_code == 200 and r.json()["role"] is None
    config = (await db_session.execute(select(SSOConfiguration).execution_options(populate_existing=True))).scalar_one()
    assert config.group_role_map == {}
    assert (await fresh(db_session, User, uid)).role == "viewer"


async def test_group_validation_filter_and_projection(client, org_a, org_a_admin_headers) -> None:
    token = await issue_token(client, org_a_admin_headers)
    h = scim_headers(token)
    uid = (await create_scim_user(client, token))["id"]
    g = await _group(client, token, "Responders", [uid])
    r = await client.post(f"{BASE}/Groups", json={"displayName": "responders"}, headers=h)
    assert r.status_code == 409 and r.json()["scimType"] == "uniqueness"
    r = await client.post(f"{BASE}/Groups", json={"displayName": "X", "members": [{"value": str(uuid.uuid4())}]},
                          headers=h)
    assert r.status_code == 400 and r.json()["scimType"] == "invalidValue"
    r = await client.post(f"{BASE}/Groups", json={"members": []}, headers=h)
    assert r.status_code == 400
    found = (await client.get(f"{BASE}/Groups", params={"filter": 'displayName eq "Responders"',
                                                        "excludedAttributes": "members"}, headers=h)).json()
    assert found["totalResults"] == 1 and found["Resources"][0]["id"] == g["id"]
    assert "members" not in found["Resources"][0]
    assert (await client.get(f"{BASE}/Groups", params={"filter": 'displayName eq "nope"'}, headers=h)).json()[
        "totalResults"] == 0
    put = {"schemas": [SCHEMA_GROUP], "displayName": "Responders", "externalId": "okta-g1", "members": []}
    out = (await client.put(f"{BASE}/Groups/{g['id']}", json=put, headers=h)).json()
    assert out["members"] == [] and out["externalId"] == "okta-g1"


# ---------------------------------------------------------------------------
# Local accounts are managed in PySOAR (security review findings)
# ---------------------------------------------------------------------------


async def test_local_account_email_cannot_be_changed(client, db_session, org_a, org_a_admin, org_a_admin_headers) -> None:
    admin_id, admin_email = org_a_admin.id, org_a_admin.email
    local = await make_user(db_session, role="analyst", organization_id=org_a.id, label="local")
    local_id, local_email = local.id, local.email
    token = await issue_token(client, org_a_admin_headers)
    h = scim_headers(token)
    for uid in (admin_id, local_id):
        patch = {"schemas": [SCHEMA_PATCH], "Operations": [{"op": "replace", "path": "userName",
                                                            "value": "attacker@evil.io"}]}
        r = await client.patch(f"{BASE}/Users/{uid}", json=patch, headers=h)
        assert r.status_code == 403 and r.json()["scimType"] == "mutability"
        assert "local accounts are managed in PySOAR" in r.json()["detail"]
        r = await client.put(f"{BASE}/Users/{uid}", json={"schemas": [SCHEMA_USER], "userName": "attacker@evil.io"},
                             headers=h)
        assert r.status_code == 403 and r.json()["scimType"] == "mutability"
    assert (await fresh(db_session, User, admin_id)).email == admin_email
    assert (await fresh(db_session, User, local_id)).email == local_email
    # Profile attributes of a local account can still be updated.
    patch = {"schemas": [SCHEMA_PATCH], "Operations": [{"op": "replace", "path": "displayName", "value": "Renamed"}]}
    r = await client.patch(f"{BASE}/Users/{local_id}", json=patch, headers=h)
    assert r.status_code == 200 and r.json()["displayName"] == "Renamed"


async def test_local_account_lifecycle_is_refused(
    client, db_session, org_a, org_a_admin, org_a_admin_headers, redis_mock,
) -> None:
    store = _stateful(redis_mock)
    admin_id, admin_email = org_a_admin.id, org_a_admin.email
    token = await issue_token(client, org_a_admin_headers)
    h = scim_headers(token)
    deactivate = {"schemas": [SCHEMA_PATCH], "Operations": [{"op": "replace", "value": {"active": False}}]}
    r = await client.patch(f"{BASE}/Users/{admin_id}", json=deactivate, headers=h)
    assert r.status_code == 403 and r.json()["scimType"] == "mutability"
    r = await client.put(f"{BASE}/Users/{admin_id}", json={"schemas": [SCHEMA_USER], "userName": admin_email,
                                                         "active": False}, headers=h)
    assert r.status_code == 403 and r.json()["scimType"] == "mutability"
    r = await client.delete(f"{BASE}/Users/{admin_id}", headers=h)
    assert r.status_code == 403 and r.json()["scimType"] == "mutability"
    assert (await fresh(db_session, User, admin_id)).is_active is True
    assert f"revoke_gen:{admin_id}" not in store
    assert (await client.get("/api/v1/auth/me", headers=org_a_admin_headers)).status_code == 200

    # A SCIM-managed account: deactivation and delete work and revoke tokens.
    managed = (await create_scim_user(client, token))["id"]
    r = await client.patch(f"{BASE}/Users/{managed}", json=deactivate, headers=h)
    assert r.status_code == 200 and store.get(f"revoke_gen:{managed}") == "1"
    other = (await create_scim_user(client, token))["id"]
    assert (await client.delete(f"{BASE}/Users/{other}", headers=h)).status_code == 204
    assert store.get(f"revoke_gen:{other}") == "1" and (await fresh(db_session, User, other)).is_active is False


async def test_group_membership_never_sets_a_local_accounts_role(
    client, db_session, org_a, org_a_admin, org_a_admin_headers,
) -> None:
    admin_id = org_a_admin.id
    token = await issue_token(client, org_a_admin_headers)
    group = await _group(client, token, "Viewers", [admin_id])
    r = await client.put(f"/api/v1/settings/scim/groups/{group['id']}", json={"role": "viewer"},
                         headers=org_a_admin_headers)
    assert r.status_code == 200
    assert (await fresh(db_session, User, admin_id)).role == "admin"


async def test_post_never_adopts_a_local_account(
    client, db_session, org_a, org_a_admin, org_a_admin_headers,
) -> None:
    org_id = org_a.id
    admin_email = org_a_admin.email
    local = await make_user(db_session, role="analyst", organization_id=org_id, label="pre-existing")
    viewer = await make_user(db_session, role="viewer", organization_id=org_id, label="pre-viewer")
    role = Role(organization_id=org_id, name="ops-admin", default_tier="read", area_tiers={"settings": "admin"})
    db_session.add(role)
    await db_session.commit()
    custom = await make_user(db_session, role="viewer", organization_id=org_id, label="pre-custom")
    custom.custom_role_id = role.id
    await db_session.commit()
    targets = {u.id: u.email for u in (local, viewer, custom)}
    token = await issue_token(client, org_a_admin_headers)
    for addr in [admin_email, *targets.values()]:
        r = await client.post(f"{BASE}/Users", json=new_user_body(addr.upper(), externalId="00u-link"),
                              headers=scim_headers(token))
        assert r.status_code == 409 and r.json()["scimType"] == "uniqueness", addr
    for uid in targets:
        user = await fresh(db_session, User, uid)
        assert user.identity_source == "local" and user.external_id is None
    assert "scim_user_adopted" not in await audit_actions(db_session, org_id)


async def test_admin_links_and_unlinks_a_local_account(
    client, db_session, org_a, org_a_admin_headers, redis_mock,
) -> None:
    store = _stateful(redis_mock)
    org_id = org_a.id
    role = Role(organization_id=org_id, name="ops-admin", default_tier="read", area_tiers={"settings": "admin"})
    db_session.add(role)
    await db_session.commit()
    target = await make_user(db_session, role="viewer", organization_id=org_id, label="to-link")
    target.custom_role_id = role.id
    await db_session.commit()
    target_id, target_email = target.id, target.email
    token = await issue_token(client, org_a_admin_headers)
    h = scim_headers(token)
    deactivate = {"schemas": [SCHEMA_PATCH], "Operations": [{"op": "replace", "value": {"active": False}}]}
    assert (await client.patch(f"{BASE}/Users/{target_id}", json=deactivate, headers=h)).status_code == 403

    # A custom-role holder with admin over settings cannot link (it would hand the IdP an account).
    holder = await make_user(db_session, role="viewer", organization_id=org_id, label="custom-admin")
    holder.custom_role_id = role.id
    await db_session.commit()
    holder_headers = bearer(holder)
    r = await client.post(f"/api/v1/settings/scim/users/{target_id}/link", json={}, headers=holder_headers)
    assert r.status_code == 403 and r.json()["detail"]["error"] == "full_admin_required"

    r = await client.post(f"/api/v1/settings/scim/users/{target_id}/link", json={"external_id": "00u-9"},
                          headers=org_a_admin_headers)
    assert r.status_code == 200, r.text
    assert r.json() == {"id": target_id, "email": target_email, "identity_source": "scim",
                        "external_id": "00u-9", "is_active": True}
    r = await client.post(f"/api/v1/settings/scim/users/{target_id}/link", json={}, headers=org_a_admin_headers)
    assert r.status_code == 409 and r.json()["detail"]["error"] == "not_local_account"
    # Linked: the IdP finds it by filter and manages it in full.
    found = (await client.get(f"{BASE}/Users", params={"filter": 'externalId eq "00u-9"'}, headers=h)).json()
    assert found["Resources"][0]["id"] == target_id
    assert (await client.patch(f"{BASE}/Users/{target_id}", json=deactivate, headers=h)).status_code == 200
    assert store.get(f"revoke_gen:{target_id}") == "1"

    r = await client.delete(f"/api/v1/settings/scim/users/{target_id}/link", headers=holder_headers)
    assert r.status_code == 403 and r.json()["detail"]["error"] == "full_admin_required"
    r = await client.delete(f"/api/v1/settings/scim/users/{target_id}/link", headers=org_a_admin_headers)
    assert r.status_code == 200 and r.json()["identity_source"] == "local" and r.json()["email"] == target_email
    r = await client.delete(f"/api/v1/settings/scim/users/{target_id}/link", headers=org_a_admin_headers)
    assert r.status_code == 409 and r.json()["detail"]["error"] == "not_scim_managed"
    reactivate = {"schemas": [SCHEMA_PATCH], "Operations": [{"op": "replace", "value": {"active": True}}]}
    assert (await client.patch(f"{BASE}/Users/{target_id}", json=reactivate, headers=h)).status_code == 403
    actions = await audit_actions(db_session, org_id)
    assert actions.count("scim_user_linked") == 1 and actions.count("scim_user_unlinked") == 1

    # An inactive local account cannot be linked.
    r = await client.post(f"/api/v1/settings/scim/users/{target_id}/link", json={}, headers=org_a_admin_headers)
    assert r.status_code == 409 and r.json()["detail"]["error"] == "user_inactive"


async def test_link_refuses_superuser_and_other_orgs(
    client, db_session, org_a, org_b, org_a_admin_headers, org_a_headers,
) -> None:
    su = await make_user(db_session, role="admin", organization_id=org_a.id, is_superuser=True, label="su-link")
    other = await make_user(db_session, role="analyst", organization_id=org_b.id, label="other-org")
    mine = await make_user(db_session, role="analyst", organization_id=org_a.id, label="mine")
    su_id, other_id, mine_id = su.id, other.id, mine.id
    for uid in (su_id, other_id):
        for method in ("post", "delete"):
            r = await client.request(method.upper(), f"/api/v1/settings/scim/users/{uid}/link",
                                     json={} if method == "post" else None, headers=org_a_admin_headers)
            assert r.status_code == 404 and r.json()["detail"]["error"] == "user_not_found"
    for method in ("post", "delete"):
        r = await client.request(method.upper(), f"/api/v1/settings/scim/users/{mine_id}/link",
                                 json={} if method == "post" else None, headers=org_a_headers)
        assert r.status_code == 403
    assert (await fresh(db_session, User, su_id)).identity_source == "local"


async def test_admin_cannot_unlink_own_account(client, db_session, org_a) -> None:
    admin = await make_user(db_session, role="admin", organization_id=org_a.id, label="scim-admin")
    admin.identity_source = "scim"
    await db_session.commit()
    admin_id = admin.id
    r = await client.delete(f"/api/v1/settings/scim/users/{admin_id}/link", headers=bearer(admin))
    assert r.status_code == 409 and r.json()["detail"]["error"] == "self_unlink"
    assert (await fresh(db_session, User, admin_id)).identity_source == "scim"


async def test_email_change_on_a_managed_account_clears_bindings(
    client, db_session, org_a, org_a_admin_headers, redis_mock,
) -> None:
    store = _stateful(redis_mock)
    org_id = org_a.id
    token = await issue_token(client, org_a_admin_headers)
    uid = (await create_scim_user(client, token))["id"]
    user = await fresh(db_session, User, uid)
    user.sso_subject = "idp-sub-1"
    user.password_reset_token = "reset-" + uuid.uuid4().hex
    user.password_reset_token_expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
    await db_session.commit()
    new_addr = email()
    patch = {"schemas": [SCHEMA_PATCH], "Operations": [{"op": "replace", "path": "userName", "value": new_addr}]}
    r = await client.patch(f"{BASE}/Users/{uid}", json=patch, headers=scim_headers(token))
    assert r.status_code == 200 and r.json()["userName"] == new_addr
    user = await fresh(db_session, User, uid)
    assert user.email == new_addr and user.sso_subject is None
    assert user.password_reset_token is None and user.password_reset_token_expires_at is None
    assert store.get(f"revoke_gen:{uid}") == "1"
    row = (await db_session.execute(
        select(AuditLog).where(AuditLog.action == "scim_user_email_changed", AuditLog.organization_id == org_id)
        .execution_options(populate_existing=True)
    )).scalar_one()
    assert '"email_domain_check": "unrestricted"' in row.new_value


async def test_email_domain_must_be_allowed_when_sso_lists_domains(
    client, db_session, org_a, org_a_admin_headers,
) -> None:
    db_session.add(SSOConfiguration(organization_id=org_a.id, issuer="https://idp.example", client_id="c",
                                    default_role="viewer", group_role_map={}, allowed_email_domains=["corp.io"]))
    await db_session.commit()
    token = await issue_token(client, org_a_admin_headers)
    h = scim_headers(token)
    r = await client.post(f"{BASE}/Users", json=new_user_body(email()), headers=h)
    assert r.status_code == 400 and r.json()["scimType"] == "invalidValue"
    created = await create_scim_user(client, token, f"u-{uuid.uuid4().hex[:6]}@CORP.io")
    patch = {"schemas": [SCHEMA_PATCH], "Operations": [{"op": "replace", "path": "userName", "value": email()}]}
    r = await client.patch(f"{BASE}/Users/{created['id']}", json=patch, headers=h)
    assert r.status_code == 400 and r.json()["scimType"] == "invalidValue"
    patch["Operations"][0]["value"] = f"v-{uuid.uuid4().hex[:6]}@corp.io"
    assert (await client.patch(f"{BASE}/Users/{created['id']}", json=patch, headers=h)).status_code == 200
