# GUARDIAN MCP — Multi-Step Attack & Information Leak Detector

**Hackurity 2026 | Problem Statement:** PS-1 — Guarding the Agent  
**Team Name:** [Visionx]  
**Team Members:** [https://github.com/chinmayee-s-kumar
https://github.com/brinda410
https://github.com/brundhas26
https://github.com/bulleanusree2006-afk]

## 1. Problem Statement - 1
Problem Statement: GUARDING THE AGENT
Subtitle: Runtime Defence for MCP-Connected AI-Tools

GUARDIAN MCP is a runtime security gateway designed to protect MCP-connected AI tools by validating tool requests, enforcing least-privilege policies, detecting suspicious multi-step activity, and blocking unauthorized operations before execution.

The system aims to provide an explainable security decision and an investigation trail through attack tracing, risk scoring, and audit logging. Its protection scope and limitations are documented and demonstrated using controlled test scenarios.

## 2. What it does

GUARDIAN MCP provides the following security capabilities:

- **MCP Runtime Security Gateway:** Intercepts tool requests and evaluates them before execution.
- **Least-Privilege Policy Engine:** Restricts access to permitted tools and actions.
- **IntentGuard:** Checks whether a requested action is authorized for the current task.
- **Attack Prevention:** Validates inputs and blocks prohibited operations.
- **Information-Flow Control:** Helps detect and prevent unsafe movement of protected information.
- **Multi-Step Attack Detection:** Correlates related tool calls to identify suspicious sequences.
- **AttackTrace:** Records related security events in an investigation timeline.
- **Risk Scoring:** Assigns a rule-based risk score and level to requests.
- **Tamper-Evident Audit Logging:** Uses SHA-256 hash linking to help detect audit-log modification.
- **Human Approval:** Provides an approval mechanism for sensitive actions, where enabled.
- **Security Dashboard:** Displays security decisions and audit events.
- **Desktop Notifications:** Notifies the user about security events on supported Windows systems.

Feature status must be verified against the submitted implementation. Only label features as working if they can be demonstrated.

## 3. Architecture

The system follows this general workflow:

```text
AI Agent / Test Harness
          |
          v
     MCP Tool Request
          |
          v
GUARDIAN MCP Security Gateway
          |
          v
  Security Policy Checks
  - Least-Privilege Policy
  - IntentGuard
  - Input Validation
  - Information-Flow Checks
  - Multi-Step Attack Detection
  - Risk Scoring
          |
          v
  Security Decision
  ALLOW / BLOCK / APPROVAL_REQUIRED
          |
          v
Tool Execution (only when permitted)
          |
          v
Audit Log + Attack Trace + Dashboard
```

The architecture diagram represents the intended workflow. Verify that each component and decision path matches the actual implementation.

## 4. How to run it

### Prerequisites

- Python 3.11
- Git
- A Windows environment for desktop notification features

### Setup

Clone the repository:

```bash
git clone https://github.com/brundhas26/GUARDIAN-MCP.git
cd GUARDIAN-MCP
```

Create a virtual environment:

```bash
python -m venv .venv
```

Activate it on Windows:

```bash
.venv\Scripts\activate
```

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

Run these commands from the project root. Confirm that the dependencies and Python version match the submitted project.

## 5. How to run the demo

### Scenario 1: Legitimate request

Run an allowed tool operation and show that the gateway permits it and returns the expected result.

### Scenario 2: Unauthorized request

Submit a prohibited tool request and demonstrate that the gateway returns `BLOCK` with an explanation and `executed: False`.

### Scenario 3: Multi-step information leak attempt

1. Read a permitted sample report.
2. Attempt a prohibited external-send operation.
3. Show the gateway's security decision.
4. Display the related AttackTrace and audit events.
5. Explain why the operation was blocked.

Use only local test tools and synthetic sample data.

### Run tests

```bash
python -m pytest -v
```

Report the actual test result from the submitted version.

### Start the dashboard

Use the verified dashboard launch command. If the dashboard is a Streamlit application at `dashboard/app.py`, the command is:

```bash
streamlit run dashboard/app.py
```

Confirm that this command works in the submitted environment before relying on it in the demo.

## 6. Tech stack

- **Language:** Python
- **Protocol:** Model Context Protocol (MCP)
- **Interface:** Streamlit
- **Testing:** pytest
- **Security:** Policy enforcement, input validation, information-flow controls, and rule-based risk scoring
- **Audit integrity:** SHA-256 hash linking
- **Desktop notifications:** winotify, if included in the final dependency list

List exact dependency versions from the submitted environment and `requirements.txt`.

## 7. Team members

| Name | 
|---|---|
| [Bulle Anusree] |
| [Brindashree R] | 
| [Brundha S] | 
| [Chinmayee S kumar] | 


## Technical Write-up and Demo

- **Technical write-up:** [Add the PDF path or accessible link]
- **Demo video:** [Add the accessible video link]

Keep the technical write-up PDF and other submitted documents in the repository, for example in `docs/`, and link them here.

## Core Deliverables and Evidence

For each deliverable, record its status as **Working**, **Partial**, or **Not done**, and specify the relevant source file, test, or demonstration.

| Deliverable | Status | Evidence |
|---|---|---|
| Runtime security gateway | [Verify] | [File/test] |
| Least-privilege policy engine | [Verify] | [File/test] |
| IntentGuard | [Verify] | [File/test] |
| Information-flow controls | [Verify] | [File/test] |
| Multi-step attack detection | [Verify] | [File/test] |
| AttackTrace | [Verify] | [File/test] |
| Risk scoring | [Verify] | [File/test] |
| Tamper-evident audit logging | [Verify] | [File/test] |
| Human approval | [Verify] | [File/test] |
| Dashboard and notifications | [Verify] | [File/test] |

## Threat Model and Limitations

**Threat model:** Unauthorized tool use, unsafe arguments, prohibited operations, and sequences of tool calls that could expose protected information.

**Assumption:** Relevant tool calls pass through the security gateway and the gateway's policies are configured correctly.

**Limitations:** Rule-based detection may miss novel attack patterns or generate false positives. Hash-linked logs help identify modification but do not alone guarantee secure storage. The current implementation should not be considered production-ready without further security testing.

## Credits and AI-Tool Disclosure

List every external repository, library, dataset, code snippet, and other resource used, with its link and what was reused.

Disclose every AI tool used and describe how it contributed to the project, in accordance with the Hackurity 2026 rules.

## License

This project is distributed under the license included in the repository. See [LICENSE](LICENSE).
