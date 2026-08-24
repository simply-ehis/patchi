---
id: llm-risk-assess-v1
name: LLM Risk Assessment
version: 1.0.0
target_agents: [LLMSecurityAgent, PromptGuardAgent, GovernanceAgent, PolicyEngineAgent]
cwe: [CWE-200, CWE-287, CWE-352, CWE-502, CWE-611, CWE-918, CWE-116, CWE-77, CWE-78]
owasp: [LLM01:2025, LLM02:2025, LLM06:2025, LLM07:2025, LLM08:2025, LLM10:2025]
confidence_boost: 0.18
---

# LLM Risk Assessment Patterns

## Risk Scoring Matrix

| Risk Factor | Weight | Description |
|-------------|--------|-------------|
| DATA_SENSITIVITY | 0.30 | PII, financial, health, or credential data passed to LLM |
| TOOL_ACCESS | 0.25 | LLM has tool access that can modify system state |
| OUTPUT_ACTION | 0.20 | LLM output is used in code execution, SQL, or rendering |
| HUMAN_OVERSIGHT | 0.15 | No human-in-the-loop for LLM-driven actions |
| MODEL_SOURCE | 0.10 | Model is from untrusted or unknown source |

**Total Risk Score**: Sum of applicable factors (0.0–1.0).
- >= 0.7: HIGH RISK — implement full guardrail stack
- 0.4–0.69: MEDIUM RISK — implement input/output guardrails
- < 0.4: LOW RISK — standard monitoring

## Risk Assessment Checks

### 1. Data Sensitivity Audit
Scan for data types passed to LLM calls:
```python
# Find all llm.chat(), llm.generate(), model.invoke() calls
# Check what variables are passed in the messages/content
```
**Patterns to flag**:
- Variable name contains: `email`, `ssn`, `credit`, `password`, `token`, `secret`, `key`
- Full HTTP request body passed to LLM
- Database records passed without field filtering
- File contents read and passed (especially log files, config files)

**Mitigation**: Apply data minimization — only pass required fields, redact PII.

### 2. Tool Access Audit
Check tool registry for risky tool categories:
```python
# HIGH RISK tools
- shell_exec, run_command, execute, bash
- db_query, sql_execute, database_run
- file_write, file_delete, file_overwrite
- network_request, http_post, curl
- send_email, send_message, deploy

# MEDIUM RISK tools
- file_read, file_list, dir_list
- http_get, fetch_url, web_scrape
- db_read_only, db_query_read

# LOW RISK tools
- calculate, format, search_memory
- summarize, translate, classify
```
→ **action**: If LLM has access to any HIGH RISK tool and no human approval gate → risk += 0.25.

### 3. Output Action Audit
Trace LLM output to:
- `exec()`, `eval()`, `compile()` → HIGH risk
- `subprocess.run()`, `os.system()` → HIGH risk
- `cursor.execute()`, `db.session.execute()` → MEDIUM risk
- `.innerHTML`, `.html()`, `.dangerouslySetInnerHTML` → MEDIUM risk
- `json.loads()`, `yaml.load()` → LOW risk (but validate schema)

### 4. Human Oversight Check
```python
# SAFE — requires confirmation
confirmed = await request_confirmation(llm_suggested_action)
if confirmed:
    execute_action(llm_suggested_action)

# DANGEROUS — automatic execution
execute_action(llm_suggested_action)
```
→ If no `confirm`/`approve`/`review` gate around LLM-driven destructive actions → risk += 0.15.

### 5. Model Source Verification
```python
# Scan for model loading from:
huggingface_hub.snapshot_download("untrusted_user/model")
AutoModel.from_pretrained("unknown-org/model")
torch.hub.load("unverified/repo")
```
→ Verify against allowlist of trusted model sources. Unknown sources → risk += 0.1.

## Risk Report Template

```json
{
  "risk_score": 0.72,
  "risk_level": "HIGH",
  "factors": [
    {"name": "DATA_SENSITIVITY", "weight": 0.30, "reason": "PII data passed to LLM in chat context"},
    {"name": "TOOL_ACCESS", "weight": 0.25, "reason": "LLM has access to shell_exec tool"},
    {"name": "OUTPUT_ACTION", "weight": 0.20, "reason": "LLM output executed via exec()"},
    {"name": "HUMAN_OVERSIGHT", "weight": 0.15, "reason": "No confirmation for code execution"}
  ],
  "recommendations": [
    "Apply data minimization — pass only required fields",
    "Add human approval gate for shell_exec tool",
    "Replace exec() with structured output + allowlist",
    "Implement confirmation dialog for all destructive actions"
  ]
}
```

## Multi-Agent Cross-Correlation
- `LLMSecurityAgent` + `GovernanceAgent` both flag LLM risk → confidence += 0.25
- `PolicyEngineAgent` matches LLM usage against policy → confidence += 0.2
- `PromptGuardAgent` intercepts injection → risk_score += 0.15
