import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.sql.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class XssNegative {
    void xss(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String q = request.getParameter("q");
        // ok: team.java.xss-taint
        response.getWriter().println(Encode.forHtml(q));
        // ok: team.java.audit.response-output, team.java.xss-html-concat
        response.getWriter().write("ok");
    }
}

// ---- v4.1
class XssNegativeV41 {
    void render(XMLWriter xmlWriter, String title, Element el, StringBuilder sb) {
        // ok: team.java.xss-writer-output
        xmlWriter.write("<br/>");
        // ok: team.java.xss-writer-output
        System.out.println(title);
        // ok: team.java.xss-writer-output
        el.text(title);
    }
}
