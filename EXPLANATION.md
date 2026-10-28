# VibeSafe: The Security Compiler for AI-Generated Code

## 🎯 The Core Mission
"Vibe Coding" is the future of development, but it is fundamentally insecure. VibeSafe is the **Security Compiler** that wraps your AI-generated code in a deterministic verification loop, ensuring your prototype is production-ready, secure, and free from supply-chain hallucinations.

---

## 🛠️ How It Works: The "VibeSafe" Architecture

VibeSafe doesn't just "chat" with your code—it uses **deterministic security engineering** to parse, audit, and patch.

### 1. The AST Security Scanner (`vibesafe/scanner.py`)
Instead of regex-based guessing, VibeSafe parses your Python code into an **Abstract Syntax Tree (AST)**. This is how the Python compiler itself "understands" your code.
- **Vulnerability Engine:** It programmatically traverses the code tree to identify dangerous patterns like `os.system` (Command Injection), `eval()` (Arbitrary Code Execution), and `exec()`.
- **Shannon Entropy Secrets:** It calculates the randomness of strings. If a hardcoded secret has a high entropy score (high randomness), it flags it as a potential hardcoded API key or password that shouldn't be in the repo.

### 2. Live Supply-Chain Auditor (`vibesafe/auditor.py`)
LLMs often hallucinate package names that don't exist (e.g., `ai-cool-lib-123`), which attackers then register with malware to compromise your machine.
- **Real-Time Verification:** The Auditor intercepts your `requirements.txt`, strips away syntax, and queries the **live PyPI (Python Package Index) JSON API**.
- **Slopsquatting Guard:** It immediately flags any package name that doesn't exist on PyPI, warning you to avoid the "slopsquatting" trap.

### 3. Autonomous Patch & Verification Loop (`vibesafe/patcher.py`)
This is the core differentiator. 
- **The Agent:** When a vulnerability is found, the system generates a secure, parameterized alternative (e.g., using `subprocess.run` instead of `os.system`).
- **The Verification Loop:** After applying the patch, VibeSafe **re-runs the AST scanner on the patched code**. If the scanner finds 0 vulnerabilities, it provides a "Proof of Fix." It proves the fix works rather than just suggesting it.

### 4. VibeSafe Security Studio (`index.html`)
The frontend is a high-end, glassmorphic security dashboard built with Tailwind CSS. It provides a visual terminal to:
- See real-time vulnerability feeds.
- Execute the Auto-Patch loop with one click.
- Audit dependencies visually.

---

## 🧩 Why It Wins
1. **It's a Compiler, Not a Chatbot:** We prove fixes mathematically with our AST verification loop.
2. **Defensive Supply-Chain Protection:** We catch AI-hallucinated malware traps in real-time.
3. **Enterprise-Grade Security:** We bring AppSec-level rigor (Entropy analysis, AST parsing) to the "Vibe Coding" environment.

---

## 🚀 How to Verify the Verification Loop
1. Paste vulnerable code (with `os.system`, hardcoded password, and `eval`) into the **Source Code Editor**.
2. Click **"Scan Vulnerabilities"** to see them highlighted.
3. Click **"Run Auto-Patch & Verify Loop"**.
4. Watch as VibeSafe patches the code and the re-scan verifies the bug count is **exactly zero**.
