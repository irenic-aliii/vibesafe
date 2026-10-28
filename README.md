# 🛡️ VibeSafe

### Security Analysis & Verification for AI-Generated Python Code

**AI makes writing code faster. VibeSafe explores how to make reviewing that code safer.**

VibeSafe is a developer-focused security workbench designed to help identify potentially dangerous Python code patterns, audit dependencies, and examine whether supported security patches resolve previously detected findings.

Built for **PromptWars × KickToTech 2026**, the project explores an important challenge in AI-assisted development: generated code still needs independent analysis, testing, and verification.

> **Project status:** Experimental prototype. Detection coverage depends on the implemented rules, and all security findings and patch results must be interpreted within those limitations.

---

## 📌 The Problem

AI coding assistants can generate functional code quickly, but generated code may still contain security weaknesses or introduce dependencies that require verification.

Three challenges motivate VibeSafe:

- **Insecure code patterns:** Functions such as `eval()` and `exec()`, or unsafe command execution patterns, can introduce serious risks depending on how they are used.
- **Dependency uncertainty:** AI-generated dependency lists may contain misspelled, nonexistent, or otherwise unverified package names.
- **Unverified fixes:** A proposed code change is not proof that a vulnerability has been resolved. The resulting code needs to be analyzed again.

VibeSafe aims to bring these checks into a single, understandable development workflow.

## ✨ Key Features

### 🔍 1. AST-Based Python Security Analysis

Uses Python's Abstract Syntax Tree (AST) to inspect source code structurally rather than relying exclusively on text matching.

The intended analysis includes selected patterns involving:

- `eval()` and `exec()`
- Potentially unsafe command execution, including `os.system()`
- Potential hardcoded secrets using string-pattern and entropy-based heuristics

**Important:** These checks cover specific patterns, not every possible vulnerability. Findings require context and review.

### 📦 2. Python Dependency Auditing

Checks declared package names against the Python Package Index (PyPI) using its package metadata API.

The goal is to identify dependencies that could not be found during the lookup and highlight packages requiring further review.

The auditor must distinguish between:

- A package successfully found.
- A package not found in the registry.
- Invalid dependency input.
- A network or registry error that prevents verification.

A missing package is not automatically proof of malicious intent. Package existence checks also do not establish that a package is safe, trustworthy, or free from known vulnerabilities.

### 🔧 3. Patch and Re-Verification Workflow

For supported patterns, VibeSafe is designed to help apply security-oriented code transformations and run the scanner against the resulting code.

The intended workflow is:

1. Analyze the original source.
2. Inspect the reported findings.
3. Apply a supported patch.
4. Re-run the same configured security checks.
5. Compare the original and subsequent findings.
6. Identify unresolved issues and limitations.

A reduction in findings demonstrates that the configured scanner no longer reports the same patterns. It does **not** prove that the entire program is secure.

Automatic transformations may not be appropriate for every context, so changes should be reviewed before use.

### 🖥️ 4. Developer Security Workbench

The application provides a web-based interface for interacting with the supported security workflows.

The intended experience brings source analysis, dependency checks, findings, and patch verification into a clear developer workflow.

The availability of individual UI actions depends on the current implementation. Only features that have been tested end to end should be considered operational.

---

## 🏗️ Architecture

VibeSafe separates the user interface from the Python security-analysis logic.

```
                 Developer
                     │
                     ▼
              Web Interface
                     │
                     ▼
             Application Server
                     │
          ┌──────────┼──────────┐
          ▼          ▼          ▼
       Scanner    Auditor    Patcher
          │          │          │
          ▼          ▼          ▼
       Python     PyPI API   Modified Code
       AST           │          │
          │          │          ▼
          │          │      Re-Scan
          └──────────┴──────────┘
                     │
                     ▼
             Findings & Results
```

### Core Components

| Component             | Responsibility                                                       |
| --------------------- | -------------------------------------------------------------------- |
| `vibesafe/scanner.py` | AST-based analysis and detection of configured Python code patterns  |
| `vibesafe/auditor.py` | Dependency checks using PyPI package metadata                        |
| `vibesafe/patcher.py` | Supported security-oriented code transformations and re-verification |
| `index.html`          | Web interface, if this remains the frontend entry point              |
| `server.py`           | Application server, if this remains the active backend entry point   |

The filenames above reflect the documented architecture. Update this table if the current repository uses different names or entry points.

### Design Principles

- Prefer deterministic analysis for explicitly defined security rules.
- Keep security logic separate from interface presentation.
- Use actual backend results instead of fabricated demonstration data.
- Make unresolved findings and inconclusive checks visible.
- Keep the architecture understandable and extensible.
- Treat security analysis as evidence for review, not as a guarantee of safety.

---

## 🚀 Getting Started

### Prerequisites

- Python 3
- `pip`
- Git
- A terminal
- An internet connection for dependency checks against PyPI

Check your Python installation:

```
python3 --version
python3 -m pip --version
```

### 1. Clone the repository

Replace `YOUR-USERNAME` with your GitHub username and use the actual repository name.

```
git clone https://github.com/YOUR-USERNAME/vibesafe.git
cd vibesafe
```

### 2. Create a virtual environment

**macOS / Linux**

```
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

If the repository contains `requirements.txt`:

```
python3 -m pip install -r requirements.txt
```

Use the dependencies specified by the project. Do not install additional packages unless the current implementation requires them.

### 4. Start the application

If `server.py` is the active application entry point:

```
python3 server.py
```

Open the local address configured by the server. The previous project instructions specified:

```
http://localhost:8080
```

If the server uses another port or entry point, follow the current source code and update these instructions accordingly.

### 5. Verify the installation

Before treating the setup as successful:

- Confirm the server starts without an exception.
- Open the application in a browser.
- Run a scan using a small, controlled Python example.
- Check that the returned findings correspond to the actual source.
- Verify that dependency-check results distinguish lookup failures from missing packages.
- Test patching and re-scanning only for patterns the patcher explicitly supports.

A page loading successfully does not establish that every backend workflow works.

---

## 🧪 Testing

Testing should cover both the individual analysis modules and the complete application workflow.

Recommended test cases include:

| Test case                                   | Expected behavior                                             |
| ------------------------------------------- | ------------------------------------------------------------- |
| Valid Python source                         | The scanner processes the input                               |
| Source containing a supported risky pattern | The configured rule reports the expected finding              |
| Source without detected patterns            | No matching findings are reported                             |
| Malformed Python source                     | A clear parsing error is returned                             |
| Empty or unsupported input                  | The input is rejected or handled explicitly                   |
| Missing dependency in a test fixture        | The auditor reports the result accurately                     |
| PyPI unavailable                            | The result indicates that verification could not be completed |
| Supported patch                             | The modified source is re-scanned                             |
| Unsuccessful patch                          | Remaining findings or transformation errors are reported      |
| Repeated analysis                           | Results correspond to the latest input                        |

Run the existing test suite using the test framework configured in the repository. For example, if the project uses `pytest`:

```
python3 -m pytest
```

Do not interpret this example as proof that the project currently has a passing test suite.

---

## 🔐 Security and Responsible Use

VibeSafe is an experimental defensive-development tool.

- Review findings in the context of the surrounding code.
- Never assume a clean scan means that code is secure.
- Review proposed code transformations before adopting them.
- Do not execute untrusted uploaded code as part of analysis.
- Do not commit API keys, passwords, access tokens, or private data.
- Treat uploaded source code as sensitive.
- Avoid permanent source-code storage unless there is an explicit requirement and an appropriate security design.
- Treat dependency existence checks as one part of supply-chain review, not a complete package-security assessment.

The tool is intended to support developer judgment, not replace code review, testing, dependency-risk analysis, or professional security assessment.

## ⚠️ Current Limitations

VibeSafe's effectiveness depends on the rules and transformations actually implemented in the current version.

Potential limitations include:

- Incomplete detection of vulnerabilities and hardcoded secrets.
- False positives and false negatives.
- Limited understanding of runtime behavior and program context.
- Dependency checks that require network access.
- Package existence checks that cannot establish package safety.
- Patch transformations that may not apply to every valid program.
- Re-scanning that checks only the configured detection rules.
- Features that may be incomplete or unverified in the current prototype.

Do not use this project as the sole security control for production software.

## 🛣️ Potential Future Improvements

Possible future work includes:

- Broader test coverage for security rules.
- More precise source-location reporting.
- Improved handling of ambiguous findings.
- Safer patch review and before/after comparisons.
- More comprehensive dependency-risk checks.
- Regression testing for supported transformations.
- Clearer evidence for every detected finding.
- Improved accessibility and developer experience.
- Persistent scan history, if required, with an explicit data-retention policy.

These are possible enhancements, not claims about currently implemented functionality.

## 🎯 Project Context

VibeSafe was developed in the context of **PromptWars × KickToTech 2026**, an AI-assisted building challenge focused on turning ideas into functional prototypes.

The project explores the intersection of:

- AI-assisted software development
- Application security
- Static analysis
- Software supply-chain awareness
- Automated code transformation
- Verification and testing

The core engineering question is:

**How can we make security checks a more visible and verifiable part of AI-assisted software development?**

## 👨‍💻 Author

**Ali Faisal**

Student developer interested in software engineering, AI-assisted development, automation, and application security.

- GitHub: [YOUR-GITHUB-USERNAME](https://github.com/YOUR-GITHUB-USERNAME)
- LinkedIn: [YOUR-LINKEDIN-PROFILE](https://www.linkedin.com/in/YOUR-LINKEDIN-USERNAME/)

## 📄 License

No license has been selected in this README. Add a `LICENSE` file and update this section once you decide how others may use, modify, and distribute the project.

---

**VibeSafe — Building with AI should be fast. Reviewing and verifying the result should be part of the process.**
