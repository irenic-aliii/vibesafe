# 🛡️ AegisPatch: The Security Compiler for AI-Generated Code

> **Built for PromptWars 2026** — Securing the future of "Vibe Coding" through deterministic AST analysis, live supply-chain auditing, and closed-loop AI verification.

---

## 🎯 The Core Problem We Solved
When developers (and students) "vibe code" using AI assistants (like Claude, ChatGPT, or Cursor), they face three invisible dangers:
1. **Insecure Code Generation:** AI frequently introduces SQL injection, command execution risks (`os.system`), dangerous functions (`eval`), and hardcoded secrets.
2. **AI Slopsquatting (Package Hallucination):** AI frequently hallucinates Python package names in `requirements.txt` that do not exist. Malicious actors register these dead names with malware, compromising your machine upon `pip install`.
3. **The "Suggestion vs. Proof" Gap:** Standard LLMs can suggest code fixes, but they **cannot prove** that the vulnerability was actually eliminated.

---

## 🏗️ What We Built (Architecture & Components)

AegisPatch is an enterprise-grade security studio featuring a **Vercel-grade glassmorphism UI** backed by a robust Python analysis engine:

1. **AST Security Scanner (`aegis_patch/scanner.py`)**
   - Parses Python Abstract Syntax Trees (AST) deterministically.
   - Detects `eval`/`exec` execution flaws, command injection risks, and hardcoded secrets using **Shannon Entropy calculation** (measuring string randomness to catch API keys and passwords).

2. **Live PyPI Supply-Chain Auditor (`aegis_patch/auditor.py`)**
   - Intercepts `requirements.txt` dependencies.
   - Queries the live PyPI JSON API in real-time to verify package existence, flagging AI-hallucinated "slopsquatting" packages instantly.

3. **Autonomous Patch & Verification Loop (`aegis_patch/patcher.py`)**
   - Automatically rewrites vulnerable AST nodes into secure equivalents (e.g., replacing `os.system` with safe `subprocess.run` lists, or `eval` with `ast.literal_eval`).
   - Re-runs the exact same static analyzer on the patched code to **mathematically prove** the vulnerability count drops from $X$ to $0$.

4. **Vercel-Grade Interactive Studio (`index.html` & `server.py`)**
   - Built with Tailwind CSS, Lucide icons, and Inter/JetBrains Mono typography.
   - Provides a split-screen security terminal, live vulnerability feeds, and one-click demo triggers for judges.

---

## 🚀 How to Run the Project Locally

1. **Clone or navigate to the project directory:**
   ```bash
   cd /Users/alipitthoo/Documents/KTT
   ```

2. **Activate your virtual environment & install dependencies:**
   ```bash
   source /Users/alipitthoo/venv/bin/activate
   pip install -r requirements.txt
   ```

3. **Launch the Web Studio:**
   ```bash
   python3 server.py
   ```
   *Open your browser at:* **`http://localhost:8080`**

---

## 🎤 The 3-Minute Judge Pitch

> *"Every team here today is building with AI. But 80% of AI-generated code contains critical vulnerabilities, hardcoded secrets, and hallucinated packages vulnerable to slopsquatting.*
> 
> *Standard LLMs can suggest fixes, but they can't prove them. So I built AegisPatch: The Security Compiler for Vibe Coding.*
> 
> *It doesn't just suggest fixes — it parses your Abstract Syntax Tree, checks live PyPI registries, auto-patches vulnerabilities, and re-scans the code to mathematically prove the bug count dropped to zero. This is how you make AI-generated software safe for production."*
