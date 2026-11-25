import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.sql.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class SqlNegative {
    void sqli(HttpServletRequest request, Connection conn) throws Exception {
        String id = request.getParameter("id");
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
        // ok: team.java.sqli-taint
        ps.setString(1, id);
        int n = Integer.parseInt(request.getParameter("n"));
        Statement st = conn.createStatement();
        // ok: team.java.sqli-taint
        st.executeQuery(String.valueOf(n));
        // ok: team.java.audit.sql-api, team.java.sqli-concat
        conn.prepareStatement("SELECT 1");
    }

    // ---- v4.2: goi lop cha execute(...) khong phai JDBC (WebGoat ProfileUpload)
    String upload(HttpServletRequest request) throws Exception {
        String fullName = request.getParameter("fullName");
        // ok: team.java.sqli-taint
        return super.execute(null, fullName);
    }
}
