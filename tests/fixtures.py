"""Golden fixtures: deliberately vulnerable and known-clean Python and Java
samples. These same fixture strings are reused for both unit tests and the
accuracy measurement in the accuracy report.
"""
PY_VULNERABLE = """'''Vulnerable Python}} sample.'''
import pickle
import subprocess
import sqlite3


def get_user(conn, uid):
    cur = conn.cursor()
    q = "SELECT * FROM users WHERE id=" + uid
    cur.execute(q)
    return cur.fetchone()


def run_tool(name, extra):
    cmd = "tool --target " + name + " " + extra
    return subprocess.call(cmd, shell=True)


def load_state(blob):
    return pickle.loads(blob)


def show(path):
    with open("/var/data/" + path) as fh:
        pass
"""

PY_CLEAN = '''"""Known-clean Python sample."""


def add(left, right):
    """Add two integers."""
    return left + right


def average(values):
    """Average a non-empty list of integers."""
    total = 0
    count = 0
    for value in values:
        total += value
        count += 1
    return total / count
'''

JAVA_VULNERABLE = """import java.sql.Statement;
import java.io.ObjectInputStream;
import javax.crypto.Cipher;

public class Vulnerable {
    public void unsafeQuery(Statement st, String acctId) {
        String sql = "SELECT * FROM accounts WHERE id=" + acctId;
        st.executeQuery(sql);
    }

    public Object unsafeRead(InputStream in) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(in);
        return ois.readObject();
    }

    public byte[] weakCrypto(String token) throws Exception {
        Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
        return c.doFinal(token.getBytes());
    }
}
"""

JAVA_CLEAN = """public class Clean {
    public int add(int left, int right) {
        return left + right;
    }

    public double average(int[] values) {
        int total = 0;
        for (int value : values) {
            total += value;
        }
        return (double) total / values.length;
    }
}
"""

# Ground truth expressed as vulnerability CATEGORIES (tool-agnostic), so the
# accuracy math is stable whether or not Bandit/PMD happen to be installed on
# the measuring machine. rule_id -> category map lives in accuracy_report.py.
PY_GROUND_TRUTH = {"sqli", "cmdi", "deser", "path"}
JAVA_GROUND_TRUTH = {"sqli", "deser", "crypto"}
