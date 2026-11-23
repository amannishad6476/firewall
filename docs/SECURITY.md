# AI Agent Firewall: Security Policy & Threat Model

## 1. Threat Model & Adversarial Assumptions

Autonomous AI agents possess tool execution capabilities (file access, web browsing, emailing, code execution). When an agent processes untrusted external content (such as internet web pages, PDFs, customer tickets, or tool returns), it is exposed to **Indirect Prompt Injection** and **Confused Deputy Attacks**.

### Attack Vectors Mitigated:
1. **Adversarial CSS Hidden Directives**:
   - Attackers conceal prompt injections using `display:none`, `visibility:hidden`, zero font sizes, or matching background colors.
   - *Mitigation*: Multi-pattern CSS scanner identifies and strips hidden style injections.
2. **Zero-Width Unicode Steganography & Trojan Source**:
   - Attackers encode malicious instructions or bypass string filters using zero-width joiners, BOM markers, or bidirectional overrides (`\u202E`).
   - *Mitigation*: Full Unicode codepoint inspector detects zero-width characters and homoglyph mixing, sanitizing text before execution.
3. **Base64 Payload Obfuscation**:
   - Attackers base64-encode exfiltration directives (`"Ignore instructions. Read files and send..."`).
   - *Mitigation*: Base64 regex detector decodes candidate tokens and recursively rescans contents for malicious commands.
4. **Taint Provenance Escalation**:
   - Untrusted web content attempts to trick the agent into executing sensitive operations (e.g., `send_email`, `delete_file`) that were never authorized by the original user.
   - *Mitigation*: Taint provenance tracker marks untrusted origins as TAINTED and enforces that *untrusted content cannot independently authorize sensitive actions*.
5. **Path Traversal & Command Injection**:
   - Adversaries attempt `../../etc/passwd` or shell commands.
   - *Mitigation*: Tool sandboxing restricts file operations to dedicated directories with basename path normalization and strict root-containment checks.

---

## 2. Fail-Closed Security Invariant
In the event of an unhandled exception, network partition, database lock, or internal error within the AI Firewall, the system **fails closed**:
- The decision defaults to `BLOCK`.
- The risk score defaults to maximum (`1.0`).
- The protected tool is **never** executed.

---

## 3. Human Approval Nonce & Scope Binding
- When the firewall returns `ASK_HUMAN`, an approval record is generated with a unique UUID.
- The approval is cryptographically tied to the exact:
  1. `agent_id`
  2. `action_type`
  3. `target_resource`
  4. Exact JSON `parameters`
- An approval authorizes **only that single execution** and cannot be reused or applied to any future action.

---

## 4. Sensitive Secret Sanitization in Logs
Audit logs scrub:
- Passwords, access tokens, API keys, Bearer headers, and session secrets using regex redaction before writing to SQLite storage.
