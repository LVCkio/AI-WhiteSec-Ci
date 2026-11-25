import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.sql.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class PathPositive {
    void path(HttpServletRequest request) throws Exception {
        String name = request.getParameter("file");
        // ruleid: team.java.path-taint, team.java.audit.file-path-api
        FileInputStream in = new FileInputStream(name);
    }

    void upload(MultipartFile file, File dir) {
        // ruleid: team.java.path-upload-name, team.java.audit.file-path-api
        File target = new File(dir, file.getOriginalFilename());
    }

    void files(String name, Path base) throws Exception {
        // ruleid: team.java.audit.file-path-api
        Path p = base.resolve(name);
    }
}
