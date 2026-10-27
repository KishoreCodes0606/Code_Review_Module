export const SAMPLE_CODES = [
  {
    id: 'py-sqli-valid',
    name: '🐍 Python: SQL Injection (Valid Syntax - Accepted)',
    language: 'python',
    isAcceptedLanguage: true,
    filename: 'user_repository.py',
    description: 'Python source code. Syntax valid and accepted for inspection.',
    code: `import sqlite3

def get_user_by_id(db_conn, uid):
    """
    Fetches user account record by ID.
    VULNERABLE: Direct string concatenation of untrusted input.
    """
    cursor = db_conn.cursor()
    query = "SELECT id, username, email, role FROM users WHERE id=" + uid
    cursor.execute(query)
    record = cursor.fetchone()
    return record

def update_user_status(db_conn, uid, active):
    cursor = db_conn.cursor()
    sql = f"UPDATE users SET active = {active} WHERE id = '{uid}'"
    cursor.execute(sql)
    db_conn.commit()
`
  },
  {
    id: 'py-syntax-err',
    name: '🐍 Python: Syntax Error (Accepted as Python, Syntax Rejected)',
    language: 'python',
    isAcceptedLanguage: true,
    filename: 'broken_calculator.py',
    description: 'Python code containing a missing colon on header line and unclosed parenthesis.',
    code: `import math

def calculate_discount(price, rate)
    # Missing colon on def statement above!
    if price < 0:
        raise ValueError("Price cannot be negative")
    
    # Unclosed parenthesis below
    total = price * (1 - (rate / 100)
    return total
`
  },
  {
    id: 'java-sqli-valid',
    name: '☕ Java: SQL Injection Concatenation (Valid Syntax - Accepted)',
    language: 'java',
    isAcceptedLanguage: true,
    filename: 'AccountDAO.java',
    description: 'Java source code. Syntax valid and accepted for inspection.',
    code: `package com.example.dao;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.sql.SQLException;

public class AccountDAO {

    public ResultSet findAccount(Connection conn, String acctId) throws SQLException {
        Statement stmt = conn.createStatement();
        String sql = "SELECT * FROM accounts WHERE id = '" + acctId + "'";
        return stmt.executeQuery(sql);
    }
}
`
  },
  {
    id: 'java-syntax-err',
    name: '☕ Java: Syntax Error (Accepted as Java, Syntax Rejected)',
    language: 'java',
    isAcceptedLanguage: true,
    filename: 'BrokenService.java',
    description: 'Java code containing missing semicolon and unclosed brace.',
    code: `package com.example.service;

public class BrokenService {

    public int computeInterest(int principal, double rate) {
        // Missing semicolon on statement below
        double interest = principal * rate
        return (int) interest;
    // Missing closing brace for method and class!
`
  },
  {
    id: 'reject-javascript',
    name: '🚫 JavaScript: Express App (REJECTED - Not Python/Java)',
    language: 'javascript',
    isAcceptedLanguage: false,
    filename: 'server.js',
    description: 'JavaScript code. Demonstrates immediate rejection because it is not Python or Java.',
    code: `const express = require('express');
const app = express();
const port = 3000;

app.get('/api/users/:id', (req, res) => {
    const userId = req.params.id;
    console.log("Fetching user: " + userId);
    res.json({ id: userId, status: "active" });
});

app.listen(port, () => {
    console.log(\`Server listening at http://localhost:\${port}\`);
});
`
  },
  {
    id: 'reject-cpp',
    name: '🚫 C++: Pointer Management (REJECTED - Not Python/Java)',
    language: 'cpp',
    isAcceptedLanguage: false,
    filename: 'main.cpp',
    description: 'C++ code with std::cout and pointers. Demonstrates rejection of non-Python/Java code.',
    code: `#include <iostream>
#include <vector>
#include <string>

int main(int argc, char* argv[]) {
    std::vector<std::string> names = {"Alice", "Bob", "Charlie"};
    for (const auto& name : names) {
        std::cout << "Hello: " << name << std::endl;
    }
    return 0;
}
`
  },
  {
    id: 'reject-html',
    name: '🚫 HTML: Web Page (REJECTED - Not Python/Java)',
    language: 'html',
    isAcceptedLanguage: false,
    filename: 'index.html',
    description: 'HTML markup code. Demonstrates rejection of markup and unsupported languages.',
    code: `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Customer Portal</title>
</head>
<body>
    <div id="container">
        <h1>Welcome</h1>
        <p>Please enter your credentials.</p>
    </div>
</body>
</html>
`
  }
];
