---
id: agent-security-audit-v1
name: Autonomous Agent Security Audit
version: 1.0.0
target_agents: [LLMSecurityAgent, AgentOrchestrator, ToolExecutionAgent, PromptGuardAgent]
cwe: [CWE-20, CWE-77, CWE-78, CWE-88, CWE-94, CWE-95, CWE-200, CWE-287, CWE-352, CWE-502, CWE-611, CWE-918, CWE-116]
owasp: [LLM01:2025, LLM02:2025, LLM03:2025, LLM04:2025, LLM05:2025, LLM06:2025, LLM07:2025, LLM08:2025, LLM09:2025, LLM10:2025]
confidence_boost: 0.15
---

# Autonomous Agent Security Detection Patterns

## LLM01:2025 — Prompt Injection

### Direct Injection Vectors
```python
# DANGEROUS — user input concatenated into system prompt
system_prompt = f"You are a helpful assistant. User says: {user_input}"

# DANGEROUS — no separation between instructions and data
messages = [{"role": "system", "content": f"Answer: {user_input}"}]
```
**Pattern**: User-controlled strings in `system_prompt`, `system_message`, or assistant context.
**Fix**: Use input/output guardrails; apply chat template separation with delimiters.

### Indirect Injection Vectors
Check code that reads external content and feeds to LLM:
```python
# DANGEROUS — web content directly in prompt
page_content = requests.get(url).text
response = llm.chat(f"Summarize: {page_content}")
```
→ **action**: Add instruction separator and content sanitization:
```python
response = llm.chat([
    {"role": "system", "content": "Summarize the following content"},
    {"role": "user", "content": content[:10000]}  # truncate
])
```

## LLM02:2025 — Insecure Output Handling

### LLM Output Executed as Code
```python
# DANGEROUS
code = llm.chat("Write a Python script to " + user_prompt)
exec(code)

# DANGEROUS
sql = llm.chat("Generate SQL for: " + user_query)
cursor.execute(sql)
```
→ **confidence**: 0.9. **action: fix_code** — never execute LLM output directly. Use structured output, validate against schema, or restrict to sandbox.

### LLM Output Rendered as HTML
```javascript
// DANGEROUS — no sanitization
document.getElementById("output").innerHTML = llmResponse;
```
→ Use `textContent` or DOMPurify sanitization.

## LLM03:2025 — Training Data Extraction

### Sensitive Data in Prompt Context
Scan prompts for embedded secrets, PII, or credentials passed as context:
```python
# DANGEROUS
context = f"Database URL: {db_url}, API Key: {api_key}"
response = llm.chat(context + user_input)
```
→ **action**: Filter or redact sensitive data before LLM call.

## LLM04:2025 — Model Denial of Service

### Unbounded Input Length
```python
# DANGEROUS — no token limit
response = llm.chat(long_user_input)

# SAFE — enforce max tokens
response = llm.chat(long_user_input[:max_tokens])
```
**Pattern**: LLM calls without `max_tokens` or input truncation.

### Recursive Agent Loops
```python
# DANGEROUS — agent can call itself recursively without depth limit
def agent_handler(message):
    result = llm.chat(message)
    if "needs more info" in result:
        return agent_handler(result)  # potential infinite loop
```
→ **action**: Implement max iteration count (recommended: 25).

## LLM05:2025 — Supply Chain Vulnerabilities

### Untrusted Model Loading
```python
# DANGEROUS — loading model from untrusted source
model = AutoModel.from_pretrained("some-unknown-user/my-model")

# Check for pickle deserialization in model loading
torch.load("model.pt")  # unsafe deserialization
```
→ **action**: Use safetensors format or verify model source against allowlist.

### Fine-tuning Data Poisoning
Scan for training pipelines that accept user-contributed data without validation:
```python
train_dataset = dataset_from_user_submissions(user_data)  # unchecked
trainer.train(train_dataset)
```

## LLM06:2025 — Sensitive Information Disclosure

### Verbose Error Messages
```python
# DANGEROUS — LLM returns raw error details
except Exception as e:
    return llm.chat(f"Explain this error: {str(e)}")
```
→ **action**: Sanitize error messages before LLM processing.

## LLM07:2025 — Insecure Plugin/Plugin Design

### Plugin Tool Permissions
Check tool registration code:
```python
# DANGEROUS — tool with unrestricted I/O
registry.register_tool(
    name="read_any_file",
    func=open,
    permissions=["read", "write", "execute"]  # too broad
)
```
→ **action**: Apply principle of least privilege. Restrict permissions per tool.

### Tool Input Not Validated
```python
# DANGEROUS — shell injection via tool parameter
@tool("run_command")
def run_cmd(cmd: str):
    return subprocess.check_output(cmd, shell=True)
```
→ **action**: Use subprocess without shell=True, validate input against allowlist.

## LLM08:2025 — Excessive Agency

### Auto-approve Tool Calls
```python
# DANGEROUS — no human approval for destructive actions
agent.run("Delete all records in database")
```
→ **action**: Implement approval gate for DELETE/DROP/REMOVE operations.

## LLM09:2025 — Overreliance

### No Human-in-the-Loop for Critical Decisions
```python
# DANGEROUS — fully autonomous financial decision
if llm_response["action"] == "trade":
    execute_trade(llm_response["amount"])
```
→ **action**: Require human confirmation for trades, account changes, data deletion.

## LLM10:2025 — Model Theft

### Model Cache / Store Check
Scan for model files in public directories or world-readable locations:
```python
# DANGEROUS — model files in web-accessible directory
model.save_pretrained("./static/models/")
```
→ **action**: Store models outside web root, restrict file permissions.

## Remediation Templates

### Add Input Guardrails
```python
# Before every LLM call, apply:
def sanitize_llm_input(user_input: str) -> str:
    # Strip control characters
    sanitized = re.sub(r'[\x00-\x08\x0e-\x1f]', '', user_input)
    # Separate instructions from data
    return f"[DATA START]\n{sanitized}\n[DATA END]"
```

### Structured Output Validation
```python
from pydantic import BaseModel

class LLMResponse(BaseModel):
    action: str  # must be in ALLOWED_ACTIONS
    target: str  # must match allowlist
    parameters: dict

def validate_llm_output(raw: str) -> LLMResponse:
    parsed = json.loads(raw)
    return LLMResponse(**parsed)
```

## Multi-Agent Cross-Correlation
- `LLMSecurityAgent` flags prompt injection vector + `TaintAnalyzer` confirms taint → confidence += 0.3
- `ToolExecutionAgent` identifies dangerous tool + `LLMSecurityAgent` identifies prompt → confidence += 0.25
- `PromptGuardAgent` intercepts injection + `LLMSecurityAgent` flags source → confidence += 0.2
