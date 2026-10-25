import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.sql.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class SecretNegative {
    // ok: team.java.hardcoded-secret
    private static final String USERNAME = "admin";
    // ok: team.java.hardcoded-secret
    private final String dbPassword = System.getenv("DB_PASSWORD");

    boolean login(String username, String password, String stored) {
        // ok: team.java.hardcoded-password-compare
        boolean isAdmin = "admin".equals(username);
        // ok: team.java.hardcoded-password-compare
        return BCrypt.checkpw(password, stored);
    }
}
