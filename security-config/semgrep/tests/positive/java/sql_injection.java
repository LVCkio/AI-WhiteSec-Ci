import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.sql.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class SqlPositive {
    void sqli(HttpServletRequest request, Connection conn) throws Exception {
        String id = request.getParameter("id");
        Statement st = conn.createStatement();
        // ruleid: team.java.sqli-taint, team.java.sqli-concat, team.java.audit.sql-api
        st.executeQuery("SELECT * FROM users WHERE id = " + id);
    }

    String spring(@RequestParam String name, JdbcTemplate jdbc) {
        // ruleid: team.java.sqli-taint, team.java.sqli-concat
        return jdbc.queryForObject("SELECT email FROM users WHERE name = '" + name + "'", String.class);
    }

    void dynamic(Connection conn, String q) throws Exception {
        // ruleid: team.java.audit.sql-api
        conn.prepareStatement(q);
    }
}
