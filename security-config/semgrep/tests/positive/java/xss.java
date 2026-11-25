import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.sql.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class XssPositive {
    void xss(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String q = request.getParameter("q");
        // ruleid: team.java.xss-taint, team.java.xss-html-concat, team.java.audit.response-output
        response.getWriter().println("<p>Results for " + q);
    }

    void out(HttpServletResponse resp, String body) throws Exception {
        // ruleid: team.java.audit.response-output
        resp.getWriter().write(body);
    }
}

// ---- v4.1
class XssPositiveV41 {
    void render(XMLWriter xmlWriter, String title, Element el) {
        // ruleid: team.java.xss-writer-output
        xmlWriter.write(title);
        // ruleid: team.java.xss-writer-output
        getPrinter().print(title);
        // ruleid: team.java.xss-writer-output
        el.html(title);
    }
}
