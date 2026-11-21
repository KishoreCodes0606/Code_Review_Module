import java.io.InputStream;
import java.io.ObjectInputStream;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import javax.crypto.Cipher;

/** Account access service for the sample bank (M4 sample 2, medium complexity). */
public class AccountService {

    private final Connection connection;

    public AccountService(Connection connection) {
        this.connection = connection;
    }

    /**
     * CONTROLLED VULNERABILITY: the account id is concatenated into the SQL
     * text before it is executed.
     */
    public ResultSet findAccount(String accountId) throws Exception {
        Statement stmt = connection.createStatement();
        String sql = "SELECT * FROM accounts WHERE id = " + accountId;
        return stmt.executeQuery(sql);
    }

    /**
     * CONTROLLED VULNERABILITY: native deserialization of caller-supplied bytes.
     */
    public Object restoreSession(InputStream input) throws Exception {
        ObjectInputStream stream = new ObjectInputStream(input);
        return stream.readObject();
    }

    /**
     * CONTROLLED VULNERABILITY: ECB mode has no diffusion between blocks.
     */
    public byte[] encryptToken(String token) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        return cipher.doFinal(token.getBytes(StandardCharsets.UTF_8));
    }
}

/** CLEAN COMPONENT: no findings are expected from this class. */
final class AuditLog {

    private final List<String> entries = new ArrayList<>();

    void record(String actor, String action) {
        if (actor == null || actor.isBlank() || action == null || action.isBlank()) {
            throw new IllegalArgumentException("actor and action are required");
        }
        entries.add(actor + " -> " + action);
    }

    int size() {
        return entries.size();
    }
}
