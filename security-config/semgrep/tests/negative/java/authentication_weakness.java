import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.sql.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class AuthNegative {
    void jwt(String token, String key) {
        // ok: team.java.auth-jwt-unverified
        Jwts.parser().setSigningKey(key).parseClaimsJws(token);
    }

    boolean login(String password, String stored, byte[] fileBytes) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        // ok: team.java.auth-weak-password-hash
        byte[] etag = md.digest(fileBytes);
        boolean same = MessageDigest.isEqual(password.getBytes(), stored.getBytes());
        boolean bearer = "Bearer".equals(tokenType);
        return same;
    }

    String renderPage(String title) {
        return title;
    }
}
