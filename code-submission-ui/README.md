# Code Submission & Language Validation Module

Part of the **AI Code Review & Security Analysis Agent** platform.

---

## 🌟 Overview

The **Code Submission Module** serves as the dedicated language gatekeeper and syntax verification gateway for source code submission.

### Core Capabilities:
1. **Strict Language Gatekeeper (Python & Java Only)**:
   - Evaluates submitted source code.
   - **Accepts**: **Python** and **Java** code.
   - **Rejects**: Any other language (JavaScript, TypeScript, C, C++, C#, PHP, Go, Rust, Ruby, HTML, CSS, SQL, Shell, etc.) with a clear explanation: *"This code is not acceptable as it is from a different language"*.
2. **Dual Ingestion Channels**:
   - **Direct Code Paste**: Interactive code editor with line numbers, active cursor line/column tracking, and error line markers.
   - **File Upload**: Drag-and-drop zone with instant parsing for Python (`.py`) and Java (`.java`) source files.
3. **Syntax Validation Engine**:
   - Line-and-column accurate syntax error reporting for accepted Python and Java code.
   - Actionable suggested fix hints and error classification (unmatched delimiters, missing colons, missing semicolons, unterminated strings).
4. **Data Model Conformance**:
   - Computes SHA-256 hash for deduplication.
   - Calculates LOC metrics (code lines, comments, blank lines, size).
   - Formulates the standardized `Submission` entity JSON schema.
5. **Interactive Test Cases**:
   - Pre-loaded test cases for Python (valid vs syntax error), Java (valid vs syntax error), and other languages (JavaScript, C++, HTML) demonstrating immediate rejection.

---

## 🚀 Quick Start

### 1. Run the Frontend (React + Vite + Tailwind CSS)

From the project root:
```bash
npm run dev
```
Or double-click `run_frontend.bat`.
Open **`http://localhost:5173`** in your browser.

### 2. (Optional) Run the Backend API Server

```bash
python server.py
```
Or double-click `run_full_system.bat` to launch both frontend and backend together.
