import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.sql.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class SecretPositive {
    // ruleid: team.java.hardcoded-secret
    private static final String DB_PASSWORD = "S3cretPass!";

    Connection connect(String url) throws Exception {
        // ruleid: team.java.hardcoded-secret
        return DriverManager.getConnection(url, "app", "hunter22");
    }

    boolean login(String username, String password) {
        // ruleid: team.java.hardcoded-password-compare
        return "admin".equals(username) && "Secret529!".equals(password);
    }
}
