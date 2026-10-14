// Utilities for hashing and UUID generation

export function generateUUID() {
  if (crypto.randomUUID) {
    return crypto.randomUUID();
  }
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
    const r = (Math.random() * 16) | 0;
    const v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}

export async function computeSHA256(text) {
  try {
    const encoder = new TextEncoder();
    const data = encoder.encode(text);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  } catch {
    // Fallback simple hash for older environments
    let hash = 0;
    for (let i = 0; i < text.length; i++) {
      const char = text.charCodeAt(i);
      hash = (hash << 5) - hash + char;
      hash |= 0;
    }
    return Math.abs(hash).toString(16).padStart(64, '0');
  }
}

/**
 * Detects programming language (Python or Java) based on filename and code heuristics
 */
export function detectLanguage(code, filename = '') {
  if (filename) {
    const ext = filename.toLowerCase().split('.').pop();
    if (ext === 'py') return { language: 'python', confidence: 1.0, reason: 'File extension .py' };
    if (ext === 'java') return { language: 'java', confidence: 1.0, reason: 'File extension .java' };
  }

  if (!code || !code.trim()) {
    return { language: 'python', confidence: 0.5, reason: 'Default language' };
  }

  let javaScore = 0;
  let pythonScore = 0;

  // Java patterns
  if (/\bpublic\s+(class|interface|enum)\b/.test(code)) javaScore += 4;
  if (/\bpublic\s+static\s+void\s+main\b/.test(code)) javaScore += 5;
  if (/\bSystem\.(out|err)\.print/.test(code)) javaScore += 3;
  if (/\bimport\s+java\./.test(code)) javaScore += 4;
  if (/\bpackage\s+[a-z0-9_.]+\s*;/.test(code)) javaScore += 4;
  if (/;\s*(\/\/.*)?$/.test(code)) javaScore += 2;
  if (/\b(extends|implements|throws|new)\b/.test(code)) javaScore += 2;
  if (/\b(String|int|boolean|double|float|long|byte|short|void)\b/.test(code)) javaScore += 2;

  // Python patterns
  if (/^\s*def\s+[a-zA-Z_][a-zA-Z0-9_]*\s*\(.*?\)\s*:/m.test(code)) pythonScore += 5;
  if (/^\s*class\s+[a-zA-Z_][a-zA-Z0-9_]*(\(.*?\))?\s*:/m.test(code)) pythonScore += 4;
  if (/^\s*elif\s+.*?:/m.test(code)) pythonScore += 5;
  if (/\bprint\(.*?\)/.test(code)) pythonScore += 3;
  if (/^\s*import\s+[a-zA-Z_0-9]+(\s*,\s*[a-zA-Z_0-9]+)*$/m.test(code)) pythonScore += 2;
  if (/^\s*from\s+[a-zA-Z_0-9.]+\s+import\s+/m.test(code)) pythonScore += 4;
  if (/^\s*if\s+__name__\s*==\s*['"]__main__['"]:/m.test(code)) pythonScore += 5;
  if (/\bNone\b|\bTrue\b|\bFalse\b/.test(code)) pythonScore += 2;
  if (/:\s*(#.*)?$/.test(code)) pythonScore += 2;

  if (javaScore > pythonScore) {
    const confidence = Math.min(0.98, Math.max(0.6, javaScore / (javaScore + pythonScore + 1)));
    return { language: 'java', confidence: Math.round(confidence * 100) / 100, reason: 'Detected Java keywords & structure' };
  } else if (pythonScore > javaScore) {
    const confidence = Math.min(0.98, Math.max(0.6, pythonScore / (javaScore + pythonScore + 1)));
    return { language: 'python', confidence: Math.round(confidence * 100) / 100, reason: 'Detected Python syntax & keywords' };
  }

  return { language: 'python', confidence: 0.5, reason: 'Fallback heuristic (Python)' };
}

/**
 * Validates Python source code syntax
 */
export function validatePython(code, maxLines = 50) {
  const errors = [];
  const warnings = [];

  if (!code || !code.trim()) {
    return {
      valid: false,
      errors: [{ line: 1, col: 1, message: 'SyntaxError: Empty code submission', rule: 'empty_input', snippet: '', hint: 'Please provide or paste Python code to analyze.' }],
      warnings: []
    };
  }

  const lines = code.split('\n');

  // Check 0: Fixed line limit gatekeeper
  if (maxLines && lines.length > maxLines) {
    const haltLine = maxLines + 1;
    return {
      valid: false,
      lineLimitExceeded: true,
      maxLines,
      lineCount: lines.length,
      stoppedAtLine: haltLine,
      errors: [
        {
          line: haltLine,
          col: 1,
          message: `CodeLimitExceeded: Submission contains ${lines.length} lines, exceeding the allowed limit of ${maxLines} lines. Validator stopped at line ${haltLine}; remaining lines were not validated.`,
          rule: 'code_line_limit_exceeded',
          snippet: (lines[maxLines] || '').trim(),
          hint: `Shorten your code to stay within ${maxLines} lines, or increase the line limit in the toolbar.`
        }
      ],
      warnings: []
    };
  }

  // Check 1: Size limits (System Design specifies max 2000 lines, 200 KB)
  const sizeBytes = new Blob([code]).size;
  if (lines.length > 2000) {
    warnings.push(`File exceeds standard limit: ${lines.length} lines (max recommended: 2,000 lines per submission).`);
  }
  if (sizeBytes > 200 * 1024) {
    warnings.push(`File size ${(sizeBytes / 1024).toFixed(1)} KB exceeds 200 KB limit.`);
  }

  // Check 2: Delimiter matching: (), [], {}
  const stack = [];
  let inSingleQuote = false;
  let inDoubleQuote = false;
  let inTripleSingle = false;
  let inTripleDouble = false;

  for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
    const lineNum = lineIdx + 1;
    const line = lines[lineIdx];

    // Check for triple quotes
    let i = 0;
    while (i < line.length) {
      const rest = line.slice(i);
      const ch = line[i];

      // Handle triple double quotes
      if (!inSingleQuote && !inDoubleQuote && !inTripleSingle && rest.startsWith('"""')) {
        inTripleDouble = !inTripleDouble;
        i += 3;
        continue;
      }

      // Handle triple single quotes
      if (!inSingleQuote && !inDoubleQuote && !inTripleDouble && rest.startsWith("'''")) {
        inTripleSingle = !inTripleSingle;
        i += 3;
        continue;
      }

      if (inTripleDouble || inTripleSingle) {
        i++;
        continue;
      }

      // Handle escape character
      if (ch === '\\') {
        i += 2;
        continue;
      }

      // Handle comments
      if (ch === '#' && !inSingleQuote && !inDoubleQuote) {
        break; // Rest of line is comment
      }

      // Handle single quotes
      if (ch === "'" && !inDoubleQuote) {
        inSingleQuote = !inSingleQuote;
        i++;
        continue;
      }

      // Handle double quotes
      if (ch === '"' && !inSingleQuote) {
        inDoubleQuote = !inDoubleQuote;
        i++;
        continue;
      }

      // If inside string literal, skip delimiter checks
      if (inSingleQuote || inDoubleQuote) {
        i++;
        continue;
      }

      // Check brackets
      if (ch === '(' || ch === '[' || ch === '{') {
        stack.push({ char: ch, line: lineNum, col: i + 1 });
      } else if (ch === ')' || ch === ']' || ch === '}') {
        if (stack.length === 0) {
          errors.push({
            line: lineNum,
            col: i + 1,
            message: `SyntaxError: unmatched '${ch}'`,
            rule: 'unmatched_closing_delimiter',
            snippet: line.trim(),
            isMissingItem: false,
            missingItem: null,
            missingDetail: null,
            hint: `Found closing bracket '${ch}' without a matching opening bracket.`
          });
        } else {
          const top = stack.pop();
          const expected = top.char === '(' ? ')' : top.char === '[' ? ']' : '}';
          if (ch !== expected) {
            errors.push({
              line: lineNum,
              col: i + 1,
              message: `SyntaxError: closing parenthesis '${ch}' does not match opening '${top.char}' on line ${top.line}`,
              rule: 'mismatched_delimiter',
              snippet: line.trim(),
              isMissingItem: false,
              missingItem: null,
              missingDetail: null,
              hint: `Expected '${expected}' to close '${top.char}' from line ${top.line}, col ${top.col}.`
            });
          }
        }
      }

      i++;
    }

    // Check for unclosed single-line strings
    if (inSingleQuote) {
      errors.push({
        line: lineNum,
        col: line.length,
        message: "SyntaxError: unterminated string literal (detected at EOL)",
        rule: 'unterminated_string',
        snippet: line.trim(),
        isMissingItem: true,
        missingItem: "closing quote (')",
        missingDetail: `Single-quote string literal on line ${lineNum} is missing closing quote.`,
        hint: "Ensure single quote string is closed with a matching single quote on the same line, or use triple quotes for multi-line strings."
      });
      inSingleQuote = false; // Reset to avoid cascade
    }
    if (inDoubleQuote) {
      errors.push({
        line: lineNum,
        col: line.length,
        message: "SyntaxError: unterminated string literal (detected at EOL)",
        rule: 'unterminated_string',
        snippet: line.trim(),
        isMissingItem: true,
        missingItem: 'closing quote (")',
        missingDetail: `Double-quote string literal on line ${lineNum} is missing closing quote.`,
        hint: "Ensure double quote string is closed with a matching double quote on the same line, or use triple quotes for multi-line strings."
      });
      inDoubleQuote = false; // Reset
    }

    // Check 3: Python header lines must end with a colon ':'
    const stripped = line.split('#')[0].trimEnd();
    if (stripped.length > 0 && !inTripleDouble && !inTripleSingle) {
      const headerRegex = /^\s*(def\s+[a-zA-Z_][a-zA-Z0-9_]*(\s*\(.*?\))?|class\s+[a-zA-Z_][a-zA-Z0-9_]*(\(.*?\))?|if\b.*|elif\b.*|else\s*|for\b.*|while\b.*|try\s*|except(\s+.*)?|finally\s*|with\b.*|async\s+def\b.*|async\s+for\b.*|async\s+with\b.*)$/;
      if (headerRegex.test(stripped)) {
        if (!stripped.endsWith(':')) {
          // If ends with open paren or backslash, it could be multi-line
          if (!stripped.endsWith('\\') && stack.length === 0) {
            errors.push({
              line: lineNum,
              col: stripped.length + 1,
              message: `SyntaxError: expected ':' at end of header statement`,
              rule: 'missing_colon',
              snippet: stripped.trim(),
              isMissingItem: true,
              missingItem: "':' (colon)",
              missingDetail: `Missing ':' at end of statement '${stripped.trim()}' on line ${lineNum}.`,
              hint: `Statements like 'def', 'if', 'for', 'class', etc., must terminate with a colon ':'.`
            });
          }
        }
      } else if (/[\+\-\*\/\=\,\<\>\&\|\^]\s*$/.test(stripped) && !stripped.endsWith('\\') && stack.length === 0) {
        errors.push({
          line: lineNum,
          col: stripped.length,
          message: "SyntaxError: invalid syntax (incomplete expression)",
          rule: "incomplete_expression",
          snippet: stripped.trim(),
          isMissingItem: true,
          missingItem: "operand / value expression",
          missingDetail: `Incomplete expression ending with an operator on line ${lineNum}.`,
          hint: "Complete the statement by providing the missing value or operand."
        });
      }
    }

    // Check 4: Check for invalid Java/C++ operators like ++, --, &&, || in Python
    if (!inTripleDouble && !inTripleSingle) {
      const codeOnly = line.split('#')[0];
      if (/\+\+|\-\-/.test(codeOnly)) {
        warnings.push(`Line ${lineNum}: '++' or '--' operator detected. Python does not have increment/decrement operators. Use '+= 1' or '-= 1'.`);
      }
      if (/&&|\|\|/.test(codeOnly) && !/['"].*(&&|\|\|).*['"]/.test(codeOnly)) {
        errors.push({
          line: lineNum,
          col: codeOnly.search(/&&|\|\|/) + 1,
          message: `SyntaxError: invalid syntax (use 'and' / 'or' instead of '&&' / '||')`,
          rule: 'invalid_boolean_operator',
          snippet: line.trim(),
          isMissingItem: false,
          missingItem: null,
          missingDetail: null,
          hint: "Python uses 'and' and 'or' for logical operators, not '&&' or '||'."
        });
      }
    }

    // Stop validating if an error has been detected - validator halts at this stage itself
    if (errors.length > 0) {
      const hasMissing = errors.some(e => e.isMissingItem);
      return {
        valid: false,
        rejectedCode: true,
        hasMissingItem: hasMissing,
        rejectionReason: hasMissing ? 'missing_item' : 'incorrect_code',
        lineLimitExceeded: false,
        maxLines,
        lineCount: lines.length,
        stoppedAtLine: errors[0].line,
        errors: [errors[0]],
        warnings
      };
    }
  }

  // Check unclosed triple quotes
  if (inTripleDouble || inTripleSingle) {
    errors.push({
      line: lines.length,
      col: 1,
      message: `SyntaxError: EOF while scanning triple-quoted string literal`,
      rule: 'unterminated_triple_quote',
      snippet: lines[lines.length - 1].trim(),
      isMissingItem: true,
      missingItem: `closing ${inTripleDouble ? '"""' : "'''"}`,
      missingDetail: "Multi-line docstring/string was opened but never closed before end of file.",
      hint: `Add matching ${inTripleDouble ? '"""' : "'''"} to close the multi-line docstring or string.`
    });
  }

  // Check unclosed brackets
  while (stack.length > 0) {
    const unclosed = stack.pop();
    const exp = unclosed.char === '(' ? ')' : unclosed.char === '[' ? ']' : '}';
    errors.push({
      line: unclosed.line,
      col: unclosed.col,
      message: `SyntaxError: '${unclosed.char}' was never closed (missing '${exp}')`,
      rule: 'unclosed_delimiter',
      snippet: (lines[unclosed.line - 1] || '').trim(),
      isMissingItem: true,
      missingItem: `closing '${exp}'`,
      missingDetail: `Missing closing '${exp}' for '${unclosed.char}' opened on line ${unclosed.line}, col ${unclosed.col}.`,
      hint: `Add matching closing bracket '${exp}' to balance structure.`
    });
  }

  const hasMissing = errors.some(e => e.isMissingItem);
  return {
    valid: errors.length === 0,
    rejectedCode: errors.length > 0,
    hasMissingItem: hasMissing,
    rejectionReason: errors.length > 0 ? (hasMissing ? 'missing_item' : 'incorrect_code') : null,
    lineLimitExceeded: false,
    maxLines,
    lineCount: lines.length,
    stoppedAtLine: errors.length > 0 ? errors[0].line : null,
    errors,
    warnings
  };
}

/**
 * Validates Java source code syntax
 */
export function validateJava(code, maxLines = 50) {
  const errors = [];
  const warnings = [];

  if (!code || !code.trim()) {
    return {
      valid: false,
      errors: [{ line: 1, col: 1, message: 'SyntaxError: Empty code submission', rule: 'empty_input', snippet: '', hint: 'Please provide or paste Java code to analyze.' }],
      warnings: []
    };
  }

  const lines = code.split('\n');

  // Check 0: Fixed line limit gatekeeper
  if (maxLines && lines.length > maxLines) {
    const haltLine = maxLines + 1;
    return {
      valid: false,
      lineLimitExceeded: true,
      maxLines,
      lineCount: lines.length,
      stoppedAtLine: haltLine,
      errors: [
        {
          line: haltLine,
          col: 1,
          message: `CodeLimitExceeded: Submission contains ${lines.length} lines, exceeding the allowed limit of ${maxLines} lines. Validator stopped at line ${haltLine}; remaining lines were not validated.`,
          rule: 'code_line_limit_exceeded',
          snippet: (lines[maxLines] || '').trim(),
          hint: `Shorten your code to stay within ${maxLines} lines, or increase the line limit in the toolbar.`
        }
      ],
      warnings: []
    };
  }

  // Check 1: Size limits
  const sizeBytes = new Blob([code]).size;
  if (lines.length > 2000) {
    warnings.push(`File exceeds standard limit: ${lines.length} lines (max recommended: 2,000 lines per submission).`);
  }
  if (sizeBytes > 200 * 1024) {
    warnings.push(`File size ${(sizeBytes / 1024).toFixed(1)} KB exceeds 200 KB limit.`);
  }

  // Check 2: Delimiters & comments
  const stack = [];
  let inBlockComment = false;
  let inString = false;
  let inChar = false;

  for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
    const lineNum = lineIdx + 1;
    const line = lines[lineIdx];

    let i = 0;
    while (i < line.length) {
      const rest = line.slice(i);
      const ch = line[i];

      // Block comments
      if (!inString && !inChar && !inBlockComment && rest.startsWith('/*')) {
        inBlockComment = true;
        i += 2;
        continue;
      }
      if (inBlockComment) {
        if (rest.startsWith('*/')) {
          inBlockComment = false;
          i += 2;
        } else {
          i++;
        }
        continue;
      }

      // Single line comments
      if (!inString && !inChar && rest.startsWith('//')) {
        break; // Ignore rest of line
      }

      // Escape chars
      if ((inString || inChar) && ch === '\\') {
        i += 2;
        continue;
      }

      // String literals
      if (ch === '"' && !inChar) {
        inString = !inString;
        i++;
        continue;
      }

      // Char literals
      if (ch === "'" && !inString) {
        inChar = !inChar;
        i++;
        continue;
      }

      if (inString || inChar) {
        i++;
        continue;
      }

      // Delimiters
      if (ch === '(' || ch === '[' || ch === '{') {
        stack.push({ char: ch, line: lineNum, col: i + 1 });
      } else if (ch === ')' || ch === ']' || ch === '}') {
        if (stack.length === 0) {
          errors.push({
            line: lineNum,
            col: i + 1,
            message: `SyntaxError: unmatched closing delimiter '${ch}'`,
            rule: 'unmatched_closing_delimiter',
            snippet: line.trim(),
            isMissingItem: false,
            missingItem: null,
            missingDetail: null,
            hint: `Encountered closing '${ch}' without a matching opening delimiter.`
          });
        } else {
          const top = stack.pop();
          const expected = top.char === '(' ? ')' : top.char === '[' ? ']' : '}';
          if (ch !== expected) {
            errors.push({
              line: lineNum,
              col: i + 1,
              message: `SyntaxError: mismatched delimiter: found '${ch}', expected '${expected}' for '${top.char}' opened on line ${top.line}`,
              rule: 'mismatched_delimiter',
              snippet: line.trim(),
              isMissingItem: false,
              missingItem: null,
              missingDetail: null,
              hint: `Replace '${ch}' with '${expected}' or verify nesting structure.`
            });
          }
        }
      }

      i++;
    }

    // Unclosed string on line
    if (inString) {
      errors.push({
        line: lineNum,
        col: line.length,
        message: 'SyntaxError: unclosed string literal',
        rule: 'unclosed_string_literal',
        snippet: line.trim(),
        isMissingItem: true,
        missingItem: 'closing quote (")',
        missingDetail: `Unclosed string literal on line ${lineNum} — missing closing double quote.`,
        hint: 'Java string literals cannot span multiple lines without concatenation (+) or text blocks (""").'
      });
      inString = false;
    }
    if (inChar) {
      errors.push({
        line: lineNum,
        col: line.length,
        message: 'SyntaxError: unclosed character literal',
        rule: 'unclosed_char_literal',
        snippet: line.trim(),
        isMissingItem: true,
        missingItem: "closing single quote (')",
        missingDetail: `Unclosed character literal on line ${lineNum} — missing closing single quote.`,
        hint: "Character literal must be enclosed in single quotes, e.g. 'a'."
      });
      inChar = false;
    }

    // Check 3: Common semicolon check for Java statements
    const cleanedLine = line.replace(/\/\/.*$/, '').trim();
    if (!inBlockComment && cleanedLine.length > 0) {
      const endsWithValidTerm = /[;{}:,]$/.test(cleanedLine);

      // Check return, throw, package, import, variable assignment/call without semicolon
      const mustSemicolon = /^(return\b|throw\b|package\b|import\b|assert\b|[a-zA-Z0-9_<>[\]]+\s+[a-zA-Z0-9_]+\s*=|System\.(out|err)\.)/.test(cleanedLine);

      if (mustSemicolon && !endsWithValidTerm && !cleanedLine.endsWith('\\')) {
        errors.push({
          line: lineNum,
          col: cleanedLine.length + 1,
          message: `SyntaxError: ';' expected`,
          rule: 'missing_semicolon',
          snippet: cleanedLine,
          isMissingItem: true,
          missingItem: "';' (semicolon)",
          missingDetail: `Missing ';' at end of statement '${cleanedLine}' on line ${lineNum}.`,
          hint: "Java statements must be terminated with a semicolon ';'."
        });
      }
    }

    // Stop validating if an error has been detected - validator halts at this stage itself
    if (errors.length > 0) {
      const hasMissing = errors.some(e => e.isMissingItem);
      return {
        valid: false,
        rejectedCode: true,
        hasMissingItem: hasMissing,
        rejectionReason: hasMissing ? 'missing_item' : 'incorrect_code',
        lineLimitExceeded: false,
        maxLines,
        lineCount: lines.length,
        stoppedAtLine: errors[0].line,
        errors: [errors[0]],
        warnings
      };
    }
  }

  if (inBlockComment) {
    errors.push({
      line: lines.length,
      col: 1,
      message: 'SyntaxError: unclosed block comment (expected */)',
      rule: 'unclosed_comment',
      snippet: lines[lines.length - 1].trim(),
      isMissingItem: true,
      missingItem: "*/ (closing comment)",
      missingDetail: "Block comment was opened with '/*' but never closed with '*/'.",
      hint: 'Add */ to close the multi-line comment.'
    });
  }

  while (stack.length > 0) {
    const unclosed = stack.pop();
    const exp = unclosed.char === '{' ? '}' : unclosed.char === '(' ? ')' : ']';
    errors.push({
      line: unclosed.line,
      col: unclosed.col,
      message: `SyntaxError: reached end of file while parsing, '${unclosed.char}' opened on line ${unclosed.line} was never closed`,
      rule: 'unclosed_delimiter',
      snippet: (lines[unclosed.line - 1] || '').trim(),
      isMissingItem: true,
      missingItem: `closing '${exp}'`,
      missingDetail: `Missing closing '${exp}' to balance opening '${unclosed.char}' on line ${unclosed.line}.`,
      hint: `Add matching '${exp}' to balance structure.`
    });
  }

  // Check 4: Check if there is at least one class or interface declaration
  if (!/\b(class|interface|enum|record)\s+[a-zA-Z_][a-zA-Z0-9_]*/.test(code)) {
    warnings.push("Notice: No class, interface, or record definition detected. Standard Java files require an enclosing class/type.");
  }

  const hasMissing = errors.some(e => e.isMissingItem);
  return {
    valid: errors.length === 0,
    rejectedCode: errors.length > 0,
    hasMissingItem: hasMissing,
    rejectionReason: errors.length > 0 ? (hasMissing ? 'missing_item' : 'incorrect_code') : null,
    lineLimitExceeded: false,
    maxLines,
    lineCount: lines.length,
    stoppedAtLine: errors.length > 0 ? errors[0].line : null,
    errors,
    warnings
  };
}

/**
 * Calculates code metrics (lines, comments, blank lines, size)
 */
export function calculateCodeMetrics(code, language) {
  if (!code) {
    return {
      lines: 0,
      codeLines: 0,
      commentLines: 0,
      blankLines: 0,
      chars: 0,
      sizeBytes: 0
    };
  }

  const lines = code.split('\n');
  let blankLines = 0;
  let commentLines = 0;
  let codeLines = 0;

  let inBlockComment = false;

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) {
      blankLines++;
      continue;
    }

    if (language === 'python') {
      if (trimmed.startsWith('#') || trimmed.startsWith('"""') || trimmed.startsWith("'''")) {
        commentLines++;
      } else {
        codeLines++;
      }
    } else {
      if (inBlockComment) {
        commentLines++;
        if (trimmed.includes('*/')) inBlockComment = false;
      } else if (trimmed.startsWith('/*')) {
        commentLines++;
        if (!trimmed.includes('*/')) inBlockComment = true;
      } else if (trimmed.startsWith('//')) {
        commentLines++;
      } else {
        codeLines++;
      }
    }
  }

  return {
    lines: lines.length,
    codeLines,
    commentLines,
    blankLines,
    chars: code.length,
    sizeBytes: new Blob([code]).size
  };
}
