import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.sql.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class CmdNegative {
    void cmd(HttpServletRequest request) throws Exception {
        String host = request.getParameter("host");
        // ok: team.java.cmdi-taint, team.java.cmd-string
        Runtime.getRuntime().exec(new String[]{"uptime"});
        // ok: team.java.audit.process-api, team.java.cmdi-taint
        Runtime.getRuntime().exec("service nginx restart");
        int port = Integer.parseInt(request.getParameter("port"));
        // ok: team.java.cmdi-taint
        Runtime.getRuntime().exec(new String[]{"nc", "-z", "localhost", String.valueOf(port)});
    }
}

// ---- v4.1
class CmdNegativeV41 {
    void run() {
        // ok: team.java.audit.commandline-api
        CommandLine cl = new CommandLine("git");
        // ok: team.java.audit.commandline-api
        cl.addArgument("status");
    }
}
