import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.sql.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class AuthPositive implements Filter {
    void jwt(String token, String key) {
        // ruleid: team.java.auth-jwt-unverified
        Jwts.parser().setSigningKey(key).parse(token);
    }

    boolean login(String password, String stored) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        // ruleid: team.java.auth-weak-password-hash
        byte[] h = md.digest(password.getBytes("UTF-8"));
        return password.equals(stored);
    }

    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        chain.doFilter(request, response);
    }
}
