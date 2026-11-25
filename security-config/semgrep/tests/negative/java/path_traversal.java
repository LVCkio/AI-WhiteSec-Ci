import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.sql.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class PathNegative {
    void path(HttpServletRequest request, File base) throws Exception {
        String name = request.getParameter("file");
        // ok: team.java.path-taint
        File safe = new File(base, FilenameUtils.getName(name));
        // ok: team.java.audit.file-path-api, team.java.path-taint
        File conf = new File("/etc/app.conf");
    }

    void upload(MultipartFile file, File dir) {
        // ok: team.java.path-upload-name
        File target = new File(dir, UUID.randomUUID().toString());
    }
}
