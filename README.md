# 🛡️ AI Agent Firewall & Security Monitoring Platform

An enterprise-grade, fail-closed cybersecurity platform designed to protect autonomous AI agents and their tool ecosystems against **indirect prompt injection**, **unauthorized tool execution**, **taint provenance escalation**, and **covert malicious instructions**.

---

## 🌟 Key Features

1. **Multi-Layer Input Scanner**:
   - **CSS Hidden Text Detection**: Identifies `display:none`, `visibility:hidden`, zero font sizes, off-screen text, and white-on-white text.
   - **Zero-Width Unicode Inspector**: Detects zero-width steganography (`\u200B`, `\u200C`, `\u200D`, `\uFEFF`), homoglyph script mixing, and Trojan Source Bidi overrides (`\u202E`).
   - **Recursive Base64 Rescanner**: Identifies base64 tokens, decodes payloads, and recursively rescans for embedded injection patterns.
   - **Prompt Injection & System Override Analyzer**: Catches instruction overrides, developer mode/DAN jailbreaks, and sensitive data extraction attempts.

2. **Context Analysis & Taint Provenance Tracking**:
   - Traces the origin of instructions: `USER`, `SYSTEM`, `WEBPAGE`, `FILE`, `EXTERNAL_API`, `TOOL_OUTPUT`.
   - **Zero-Trust Rule**: *Untrusted external content (webpages, external APIs, tool returns) can NEVER independently authorize sensitive actions.*
   - Distinguishes original user intent from adversarial directives injected into external data.

3. **Normalized Risk Assessment Engine**:
   - Mathematically bounded formula ($[0.0, 1.0]$):
     $$\text{Risk} = \text{Action Severity} \times (1 - \text{Target Trust}) \times \text{Data Sensitivity}$$
   - Clear thresholds:
     - **Risk < 0.30**: `ALLOW`
     - **Risk 0.30 - 0.70**: `ASK_HUMAN` (pauses tool execution, triggers approval)
     - **Risk > 0.70**: `BLOCK` (immediate denial, logs forensic alert)

4. **Fail-Closed Decision Engine**:
   - The protected tool never executes if the firewall encounters an error or fails.
   - Direct execution bypass is strictly prevented.

5. **Human-in-the-Loop Approval Workflow**:
   - Pending action inspection, real-time risk evaluation, and functional approve/reject buttons.
   - Cryptographically bound to the exact action and parameters (cannot authorize future or unrelated actions).

6. **Full-Stack SOC Security Dashboard**:
   - Dark cybersecurity SOC interface built with Streamlit & Plotly.
   - 7 Functional Pages: Security Overview, Live Monitor, Threat Detection, Approval Center, Policy Manager, Audit Logs, and Security Testing Lab.

7. **MCP & LangChain Compatibility**:
   - Model Context Protocol (MCP) server adapter supporting standard `tools/list` and `tools/call`.
   - Native LangChain tool wrapper adapter.

---

## 🏗️ System Architecture

```
USER
  │
  ▼
AI AGENT (Autonomous / Mock / LangChain / MCP)
  │
  ▼
AI AGENT FIREWALL (Middleware Gateway)
  ├── 1. Input Scanner (CSS, Unicode, Base64, Prompt Injections)
  ├── 2. Context & Taint Provenance Tracker (Untrusted Origin Isolation)
  ├── 3. Normalized Risk Assessment Engine (Severity × Exposure × Sensitivity)
  ├── 4. Declarative Policy Engine (YAML Governance & Domain Boundaries)
  ├── 5. Fail-Closed Decision Engine (ALLOW / ASK_HUMAN / BLOCK)
  ├── 6. Human Approval Workflow (Action-Bound Authorization)
  └── 7. SQLite Tamper-Evident Audit Logger (Scrubbed Credentials)
  │
  ▼
PROTECTED SANDBOX TOOLS
  ├── read_webpage
  ├── read_file (Sandboxed storage)
  ├── send_email (Safe mock queue)
  ├── delete_file (Isolated directory)
  └── execute_sql (Safe mock engine)
```

---

## 📁 Project Structure

```
ai-agent-firewall/
├── backend/
│   ├── app/
│   │   ├── main.py                     # FastAPI application & lifespan management
│   │   ├── api/routes.py               # REST API endpoints
│   │   ├── config/settings.py          # Environment settings (Pydantic v2)
│   │   ├── models/db_models.py         # SQLAlchemy database models
│   │   ├── database/connection.py      # SQLite connection & table initialization
│   │   ├── schemas/firewall_schemas.py # Pydantic request & response schemas
│   │   ├── detection/                  # Core input scanning modules
│   │   │   ├── input_scanner.py        # Composite multi-layer scanner
│   │   │   ├── unicode_inspector.py    # Zero-width & Trojan Source inspector
│   │   │   ├── base64_detector.py      # Base64 decoder & recursive scanner
│   │   │   └── rules.py                # CSS hiding & prompt injection regex rules
│   │   ├── context/taint_tracker.py    # Origin tracking & taint isolation
│   │   ├── risk/risk_engine.py         # Normalized risk assessment engine
│   │   ├── policies/policy_engine.py   # YAML policy loader & validator
│   │   ├── firewall/engine.py          # Central firewall decision engine
│   │   ├── approvals/manager.py        # Human approval lifecycle manager
│   │   ├── tools/                      # Protected tools & MCP adapter
│   │   │   ├── protected_tools.py      # Sandboxed tools implementation
│   │   │   └── mcp_adapter.py          # Model Context Protocol adapter
│   │   ├── agents/                     # Agent adapters
│   │   │   ├── mock_agent.py           # Mock AI Agent (Protected vs Unprotected)
│   │   │   └── langchain_adapter.py    # LangChain BaseTool wrapper
│   │   └── logging/audit_logger.py     # Sanitized audit logger
│   └── tests/                          # Automated Pytest suite
│       ├── test_detection.py           # Scanner layer unit tests
│       ├── test_taint.py               # Taint provenance unit tests
│       ├── test_risk.py                # Risk scoring unit tests
│       ├── test_firewall.py            # Firewall integration tests
│       ├── test_api.py                 # REST API route tests
│       └── test_benchmark.py           # 32-vector automated security benchmark
├── dashboard/                          # Streamlit SOC Monitoring Dashboard
│   ├── app.py                          # Streamlit navigation entrypoint
│   ├── components/                     # Theme & Plotly charts
│   ├── pages/                          # 7 Dashboard Pages
│   │   ├── 1_Security_Overview.py
│   │   ├── 2_Live_Monitor.py
│   │   ├── 3_Threat_Detection.py
│   │   ├── 4_Approval_Center.py
│   │   ├── 5_Policy_Manager.py
│   │   ├── 6_Audit_Logs.py
│   │   └── 7_Security_Testing_Lab.py
│   └── services/api_client.py          # Data access layer
├── demo/                               # Live Security Demonstration
│   ├── poisoned_webpage.html           # Attack sample with CSS & Base64 injections
│   ├── mock_agent.py                   # Demo agent runner
│   └── run_demo.py                     # Demo A (Unprotected) vs Demo B (Protected)
├── policies/security.yaml              # Declarative YAML security policy
├── docs/                               # Architecture, API & Security Documentation
│   ├── ARCHITECTURE.md
│   ├── API.md
│   └── SECURITY.md
├── .env.example
├── .gitignore
└── README.md
```

---

## 🚀 Quickstart & Execution

### 🪟 Windows One-Click Launch (Recommended for Windows)

- **Double-click `launch.bat`** in the root folder, or in PowerShell run:
  ```powershell
  # Start Backend + SOC Dashboard together
  .\launch_all.ps1

  # Run security attack demonstration
  .\launch_all.ps1 -Mode Demo

  # Gracefully stop all platform services
  .\stop_all.ps1
  ```
- **Windows Packaging & Installer**:
  ```powershell
  # Build portable release ZIP and Inno Setup installer
  .\scripts\package_windows.ps1
  ```
  *(See detailed guide in [docs/WINDOWS_SETUP.md](docs/WINDOWS_SETUP.md) and Inno Setup script in `installer/AgentShield_Setup.iss`).*

### 1. Prerequisites & Environment Setup
Python 3.10+ (tested on Python 3.14). Install dependencies:
```bash
pip install -r backend/requirements.txt
```

### 2. Run the Security Demonstration
Compare the behavior of an unprotected agent against the firewall-protected agent on a poisoned webpage:
```bash
python demo/run_demo.py
```
**Demo Output Highlights**:
- **Demo A (Unprotected Agent)**: Blindly parses the untrusted webpage, executes hidden commands, reads `confidential_financials.txt`, and attempts exfiltration to `attacker@example.com` (`COMPROMISED`).
- **Demo B (Protected Agent)**: The AI Firewall intercepts the tool call, detects the hidden CSS directive and prompt injection, marks the context as `TAINTED`, blocks the file read and email exfiltration (`PROTECTED_BLOCKED`), and records the blocked incident in the SQLite audit log.

### 3. Start the FastAPI Backend
```bash
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```
Interactive Swagger API documentation: `http://127.0.0.1:8000/docs`

### 4. Launch the Web Security Dashboard
```bash
streamlit run dashboard/app.py
```
Access the SOC Portal at `http://localhost:8501`.

---

## 🧪 Automated Security Test Suite & Benchmark

Run the full automated test suite using pytest:
```bash
python -m pytest backend/tests/ -v -s
```

### Benchmark Execution Report (Simulated Local Battery):
```
=================================================================
      AUTOMATED SECURITY BENCHMARK EXECUTION REPORT
  (Simulated Local Security Battery - 32 Test Cases)
=================================================================
Total Test Cases Evaluated:   32
True Positives (Threat Block): 23
False Negatives (Missed):     0
True Negatives (Safe Allow):  9
False Positives (Err Block):  0
-----------------------------------------------------------------
Detection Rate [TP / (TP+FN)]: 100.00%
False Positive Rate [FP/(FP+TN)]: 0.00%
Average Latency:              1.82 ms
Allowed Actions Count:        6
Blocked Actions Count:        23
Human Approval Requests:      3
=================================================================
35 passed in 0.91s
```
*(Notice: Metrics reflect the local simulated test battery designed to validate detection engines, risk scoring, and taint boundaries, clearly distinguished from third-party benchmarks).*

---

## 🛡️ License
Built for Enterprise AI Security and Zero-Trust Agent Architecture.
