// Deliberately vulnerable fixture (CWE-89). Never executed; scanned in CI only.
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;

public class SqlInjection {
    public ResultSet find(Connection conn, String name) throws Exception {
        Statement stmt = conn.createStatement();
        String query = String.format("SELECT * FROM users WHERE name = '%s'", name);
        return stmt.executeQuery(query);
    }
}
