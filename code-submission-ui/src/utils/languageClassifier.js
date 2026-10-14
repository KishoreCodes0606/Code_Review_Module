/**
 * Comprehensive Language Classifier & Gatekeeper
 * Strictly accepts ONLY Python and Java.
 * Detects and rejects any other language (JavaScript, C/C++, C#, PHP, Go, Rust, Ruby, HTML, CSS, SQL, Shell, etc.).
 */

export function classifyLanguage(code, filename = '') {
  if (!code || !code.trim()) {
    return {
      isAcceptable: false,
      language: 'unknown',
      languageName: 'Empty Input',
      confidence: 0,
      reason: 'No code provided',
      evidence: []
    };
  }

  // 1. Check file extension first if filename is present
  if (filename) {
    const ext = filename.toLowerCase().split('.').pop();
    if (ext === 'py') {
      return {
        isAcceptable: true,
        language: 'python',
        languageName: 'Python (.py)',
        confidence: 1.0,
        reason: 'Confirmed from .py file extension',
        evidence: ['Valid Python file extension: .py']
      };
    }
    if (ext === 'java') {
      return {
        isAcceptable: true,
        language: 'java',
        languageName: 'Java (.java)',
        confidence: 1.0,
        reason: 'Confirmed from .java file extension',
        evidence: ['Valid Java file extension: .java']
      };
    }
    // Any other extension is explicitly rejected immediately!
    const extMap = {
      js: 'JavaScript',
      jsx: 'JavaScript (React)',
      ts: 'TypeScript',
      tsx: 'TypeScript (React)',
      c: 'C',
      cpp: 'C++',
      cc: 'C++',
      h: 'C/C++ Header',
      hpp: 'C++ Header',
      cs: 'C# (.NET)',
      php: 'PHP',
      rb: 'Ruby',
      go: 'Go (Golang)',
      rs: 'Rust',
      html: 'HTML',
      htm: 'HTML',
      css: 'CSS',
      scss: 'SCSS',
      sql: 'SQL',
      sh: 'Bash/Shell',
      bash: 'Bash/Shell',
      kt: 'Kotlin',
      swift: 'Swift'
    };
    const detectedName = extMap[ext] || `.${ext} file`;
    return {
      isAcceptable: false,
      language: ext,
      languageName: detectedName,
      confidence: 1.0,
      reason: `File extension .${ext} is not accepted. Only Python (.py) and Java (.java) are allowed.`,
      evidence: [`Detected file extension: .${ext} (${detectedName})`]
    };
  }

  // 2. Content-based heuristic classification
  const lines = code.split('\n');
  const scores = {
    python: 0,
    java: 0,
    javascript: 0,
    c_cpp: 0,
    csharp: 0,
    php: 0,
    ruby: 0,
    go: 0,
    rust: 0,
    html: 0,
    css: 0,
    sql: 0,
    shell: 0
  };

  const evidence = {
    python: [],
    java: [],
    other: []
  };

  // Check JavaScript / TypeScript
  if (/\b(console\.(log|error|warn|info)|document\.getElementById|window\.|localStorage\.)\b/.test(code)) {
    scores.javascript += 6;
    evidence.other.push('JavaScript DOM/Console APIs (console.log / document)');
  }
  if (/\b(const|let|var)\s+[a-zA-Z0-9_$]+\s*=/.test(code)) {
    scores.javascript += 4;
    evidence.other.push('JavaScript variable declarations (const / let / var)');
  }
  if (/=>\s*\{?/.test(code) && !code.includes('=>') && !code.includes('==>')) {
    // Arrow function
    scores.javascript += 4;
    evidence.other.push('Arrow function syntax (=>)');
  }
  if (/\b(function\s*\([a-zA-Z0-9_$,\s]*\)|async\s+function|export\s+default|import\s+.*\s+from\s+['"][^'"]+['"])/.test(code)) {
    scores.javascript += 5;
    evidence.other.push('JavaScript function / ES Module import');
  }
  if (/\b(require\(['"][^'"]+['"]\)|module\.exports\b)/.test(code)) {
    scores.javascript += 5;
    evidence.other.push('Node.js CommonJS syntax (require / module.exports)');
  }

  // Check C / C++
  if (/#include\s*<[a-zA-Z0-9_.]+>|#include\s*"[a-zA-Z0-9_.]+"/.test(code)) {
    scores.c_cpp += 7;
    evidence.other.push('C/C++ preprocessor directive (#include)');
  }
  if (/\b(std::cout|std::cin|std::endl|std::string|std::vector)\b/.test(code)) {
    scores.c_cpp += 7;
    evidence.other.push('C++ Standard Library namespaces (std::cout / std::endl)');
  }
  if (/\b(printf|scanf|malloc|free|cout\s*<<)\b/.test(code)) {
    scores.c_cpp += 5;
    evidence.other.push('C standard I/O (printf / malloc)');
  }

  // Check C#
  if (/\busing\s+System(\.[a-zA-Z0-9_]+)*\s*;/.test(code)) {
    scores.csharp += 7;
    evidence.other.push('C# System namespace import (using System;)');
  }
  if (/\bConsole\.(WriteLine|ReadLine|Write)\b/.test(code)) {
    scores.csharp += 7;
    evidence.other.push('C# Console.WriteLine call');
  }
  if (/\b(namespace\s+[a-zA-Z0-9_.]+|get\s*;\s*set\s*;)/.test(code)) {
    scores.csharp += 5;
    evidence.other.push('C# namespace or auto-property');
  }

  // Check PHP
  if (/<\?php|\b\$_POST\b|\b\$_GET\b|\b\$_SERVER\b|\$[a-zA-Z0-9_]+->/.test(code)) {
    scores.php += 8;
    evidence.other.push('PHP opening tag or variables ($var, $_POST, $this->)');
  }

  // Check Go
  if (/\bpackage\s+main\b|\bfunc\s+main\(\)|\bimport\s+\(\s*"fmt"|\bfmt\.Println\b/.test(code)) {
    scores.go += 7;
    evidence.other.push('Go package main / fmt.Println syntax');
  }

  // Check Rust
  if (/\bfn\s+main\(\)|\blet\s+mut\s+|\bprintln!\b|\buse\s+std::/.test(code)) {
    scores.rust += 7;
    evidence.other.push('Rust fn main / println! macro / let mut syntax');
  }

  // Check HTML / XML
  if (/<!DOCTYPE\s+html|<html[\s>]|<div[\s>]|<p[\s>]|<script[\s>]|<\/div>|<\/body>/i.test(code)) {
    scores.html += 8;
    evidence.other.push('HTML / XML markup tags (<div>, <html>)');
  }

  // Check CSS
  if (/(\.[a-zA-Z0-9_-]+|#[a-zA-Z0-9_-]+|\bbody|\bheader)\s*\{\s*(display|color|margin|padding|background|font-size)\s*:/i.test(code)) {
    scores.css += 7;
    evidence.other.push('CSS rule definitions & properties (margin, padding, color)');
  }

  // Check SQL
  if (/\b(SELECT\s+.*\s+FROM\s+[a-zA-Z0-9_]+|INSERT\s+INTO\s+[a-zA-Z0-9_]+|CREATE\s+TABLE\s+[a-zA-Z0-9_]+|DROP\s+TABLE|ALTER\s+TABLE)\b/i.test(code) && !code.includes('cur.execute') && !code.includes('stmt.executeQuery')) {
    scores.sql += 7;
    evidence.other.push('Raw SQL query statement (SELECT / INSERT INTO / CREATE TABLE)');
  }

  // Check Shell / Bash
  if (/^#!\/bin\/(bash|sh)|^\s*(echo\s+["'].*["']|export\s+[A-Z_]+=|grep\s+-|chmod\s+\+x)/m.test(code)) {
    scores.shell += 6;
    evidence.other.push('Bash / Shell commands or shebang');
  }

  // Check Python
  if (/^\s*def\s+[a-zA-Z_][a-zA-Z0-9_]*\s*\(.*?\)\s*:/m.test(code)) {
    scores.python += 5;
    evidence.python.push("Python function header ('def ...:')");
  }
  if (/^\s*class\s+[a-zA-Z_][a-zA-Z0-9_]*(\(.*?\))?\s*:/m.test(code)) {
    scores.python += 4;
    evidence.python.push("Python class declaration ('class ...:')");
  }
  if (/^\s*elif\s+.*?:/m.test(code)) {
    scores.python += 5;
    evidence.python.push("Python 'elif' keyword");
  }
  if (/^\s*from\s+[a-zA-Z_0-9.]+\s+import\s+/m.test(code) || /^\s*import\s+[a-zA-Z_0-9]+(\s*,\s*[a-zA-Z_0-9]+)*$/m.test(code)) {
    scores.python += 4;
    evidence.python.push('Python module import statement');
  }
  if (/\bprint\(.*?\)/.test(code) && !code.includes(';') && !code.includes('{')) {
    scores.python += 3;
    evidence.python.push('Python print() function');
  }
  if (/^\s*if\s+__name__\s*==\s*['"]__main__['"]:/m.test(code)) {
    scores.python += 6;
    evidence.python.push('Python main entry idiom (if __name__ == "__main__":)');
  }
  if (/\b(None|True|False)\b/.test(code)) {
    scores.python += 2;
    evidence.python.push("Python capitalized booleans / None");
  }
  if (/^\s*#.*$/m.test(code) && !code.includes('//')) {
    scores.python += 2;
    evidence.python.push('Python comment style (#)');
  }

  // Check Java
  if (/\bpublic\s+(class|interface|enum|record)\s+[a-zA-Z_][a-zA-Z0-9_]*/.test(code)) {
    scores.java += 6;
    evidence.java.push("Java public class/interface declaration");
  }
  if (/\bpublic\s+static\s+void\s+main\s*\(\s*String\s*(\[\s*\]\s+[a-zA-Z_]|[a-zA-Z_]+\s*\[\s*\])/.test(code)) {
    scores.java += 8;
    evidence.java.push("Java main method signature: public static void main(String[] args)");
  }
  if (/\bSystem\.(out|err)\.(println|print|printf)\s*\(/.test(code)) {
    scores.java += 5;
    evidence.java.push("Java System.out.println statement");
  }
  if (/\bimport\s+java\.[a-zA-Z0-9_.]+\s*;/.test(code)) {
    scores.java += 6;
    evidence.java.push("Java standard library import (import java.*)");
  }
  if (/\bpackage\s+[a-z0-9_.]+\s*;/.test(code)) {
    scores.java += 5;
    evidence.java.push("Java package declaration (package ...;)");
  }
  if (/\b(throws\s+[a-zA-Z0-9_]+Exception|@Override|try\s*\([a-zA-Z0-9_<>[\]]+\s+[a-zA-Z_]+\s*=)/.test(code)) {
    scores.java += 4;
    evidence.java.push("Java exception throws / try-with-resources / @Override");
  }

  // Find the highest scoring language
  let maxLang = 'unknown';
  let maxScore = 0;

  for (const [lang, score] of Object.entries(scores)) {
    if (score > maxScore) {
      maxScore = score;
      maxLang = lang;
    }
  }

  // If score is negligible (< 2) and code has curly braces and semicolons, check if it's C/JS or Java
  if (maxScore < 3) {
    if (code.includes('def ') || code.includes('import ') || code.includes(':') && !code.includes('{')) {
      maxLang = 'python';
      maxScore = 3;
      evidence.python.push('Python indentation and block structure');
    } else if (code.includes('public ') || code.includes('class ') && code.includes(';')) {
      maxLang = 'java';
      maxScore = 3;
      evidence.java.push('Java class structure with semicolons');
    }
  }

  const names = {
    python: 'Python',
    java: 'Java',
    javascript: 'JavaScript / TypeScript',
    c_cpp: 'C / C++',
    csharp: 'C# (.NET)',
    php: 'PHP',
    go: 'Go (Golang)',
    rust: 'Rust',
    ruby: 'Ruby',
    html: 'HTML / Markup',
    css: 'CSS / Styling',
    sql: 'SQL Database Script',
    shell: 'Shell / Bash Script',
    unknown: 'Unrecognized / Non-Code'
  };

  // If detected as Python
  if (maxLang === 'python' && scores.python > 0 && scores.python >= scores.javascript && scores.python >= scores.c_cpp) {
    return {
      isAcceptable: true,
      language: 'python',
      languageName: 'Python',
      confidence: Math.min(0.99, Math.max(0.65, scores.python / 10)),
      reason: 'Code verified as Python source.',
      evidence: evidence.python
    };
  }

  // If detected as Java
  if (maxLang === 'java' && scores.java > 0 && scores.java >= scores.csharp && scores.java >= scores.c_cpp) {
    return {
      isAcceptable: true,
      language: 'java',
      languageName: 'Java',
      confidence: Math.min(0.99, Math.max(0.65, scores.java / 10)),
      reason: 'Code verified as Java source.',
      evidence: evidence.java
    };
  }

  // If detected as another language or unknown -> REJECT!
  const detectedName = names[maxLang] || 'Other Language';
  return {
    isAcceptable: false,
    language: maxLang,
    languageName: detectedName,
    confidence: maxScore > 0 ? Math.min(0.95, maxScore / 8) : 0,
    reason: `This code is not acceptable as it belongs to a different language (${detectedName}). This module strictly accepts only Python and Java source code.`,
    evidence: evidence.other.length > 0 ? evidence.other : [`Characteristics match ${detectedName} rather than Python or Java`]
  };
}
