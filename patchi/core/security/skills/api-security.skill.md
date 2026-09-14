---
id: api-security-v1
name: API Security Audit
version: 1.0.0
target_agents: [ApiSecurityAgent, AuthSecurityAgent, RateLimitAgent, SecurityProber, BrowserTesterAgent, BusinessLogicAgent, WebSocketSecurityAgent]
cwe: [CWE-200, CWE-287, CWE-284, CWE-352, CWE-799, CWE-862, CWE-918]
owasp: [API1:2023, API2:2023, API3:2023, API4:2023, API5:2023, API6:2023, API7:2023, API8:2023]
confidence_boost: 0.12
---

# API Security Detection Patterns

## API1:2023 — Broken Object Level Authorization
### Pattern: Missing Ownership Check
```python
# DANGEROUS — no user-object ownership verification
@route("/api/orders/{order_id}")
def get_order(order_id):
    order = db.query(Order).filter_by(id=order_id).first()
    return jsonify(order)


# SAFE — ownership check present
@route("/api/orders/{order_id}")
def get_order(order_id):
    order = db.query(Order).filter_by(id=order_id, user_id=current_user.id).first()
    if not order:
        abort(403)
    return jsonify(order)
```
**Check**: Any route using `{id}` param that queries by ID without user context filter.
**Severity**: Critical for PUT/DELETE endpoints with `{id}` param and no ownership check.

## API3:2023 — Broken Object Property Level Mapping
### Mass Assignment Detection
```python
# DANGEROUS — no field whitelist
user.update(request.json)

# SAFE — explicit field allowlist
allowed = ["name", "email"]
for field in allowed:
    if field in request.json:
        setattr(user, field, request.json[field])
```
**Pattern**: `\.(update|put|patch|save)\(request\.(json|data|form|args)\)` without field filtering.

## API4:2023 — Unrestricted Resource Consumption
### Pagination Missing / Unbounded
```python
# DANGEROUS — no pagination
return jsonify([item.to_dict() for item in db.query(Item).all()])

# SAFE — paginated
page = request.args.get("page", 1, type=int)
per_page = min(request.args.get("per_page", 20, type=int), 100)
items = db.query(Item).paginate(page=page, per_page=per_page)
```
**Pattern**: Route returning collections with `.all()` or `SELECT *` without `.limit()` or `.paginate()`.

### Rate Limit Missing
Check route decorators: absence of `@ratelimit` or `@throttle` on POST/PUT/DELETE endpoints.
→ Cross-correlate with RateLimitAgent.

## API5:2023 — Broken Function Level Authorization
### Admin Endpoint Accessible Without Role Check
```python
# DANGEROUS — no admin check
@route("/api/admin/users")
def admin_users(): ...


# SAFE — role check present
@route("/api/admin/users")
@requires_role("admin")
def admin_users(): ...
```
**Pattern**: Routes containing `/admin/` or `/internal/` without role/permission decorator.

## API6:2023 — Unrestricted Access to Sensitive Business Flows
### Excessive Data Exposure
```python
# DANGEROUS — returns entire User model (includes password_hash)
return jsonify(user.__dict__)

# SAFE — explicit fields only
return jsonify({"id": user.id, "name": user.name, "email": user.email})
```
**Pattern**: `__dict__` or `.to_dict()` or `vars(` on sensitive models in API response.

## API7:2023 — Server Side Request Forgery
Matches `ssrf-detection` patterns. Cross-correlate with SSRFDetector.

## API8:2023 — Security Misconfiguration
### CORS Overly Permissive
```python
# DANGEROUS
CORS(app, resources={r"/api/*": {"origins": "*"}})

# SAFE
CORS(app, resources={r"/api/*": {"origins": ["https://app.example.com"]}})
```

### Authentication Bypassed for Internal Networks
```python
# DANGEROUS — trust on network boundary
if request.remote_addr.startswith("10."):
    current_user = get_admin_user()
    # no further auth
```
→ **action: escalate** (requires review)

## OpenAPI / Swagger Audit
### Security Schemes Missing
Check `openapi.json` or `swagger.yaml` for:
- `securitySchemes` missing → lack of auth documentation
- `bearerAuth` or `oauth2` or `apiKey` missing from all paths → no auth enforcement
- `schemes: ["http"]` (not https) → transport security gap

## Remediation Templates

### Add Ownership Check
```python
# Auto-fix template
item = db.query(Item).filter_by(id=item_id, owner_id=current_user.id).first()
if not item:
    abort(403)
```

### Add Rate Limiting
```python
from flask_limiter import Limiter

limiter = Limiter(app, key_func=lambda: current_user.id)


@route("/api/orders")
@limiter.limit("30/minute")
def create_order(): ...
```

## Multi-Agent Cross-Correlation
- `ApiSecurityAgent` + `AuthSecurityAgent` both flag same route → confidence += 0.2
- `RateLimitAgent` + `ApiSecurityAgent` on same resource → confidence += 0.15
- `SecurityProber` confirms open endpoint → confidence += 0.25
