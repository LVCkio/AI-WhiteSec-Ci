import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.sql.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class CmdPositive {
    void cmd(HttpServletRequest request) throws Exception {
        String host = request.getParameter("host");
        // ruleid: team.java.cmdi-taint, team.java.cmd-string
        Runtime.getRuntime().exec("ping -c 1 " + host);
    }

    void proc(String cmd) throws Exception {
        // ruleid: team.java.audit.process-api
        new ProcessBuilder(cmd).start();
    }
}

// ---- v4.1
class CmdPositiveV41 {
    void run(String exe, String file) {
        // ruleid: team.java.audit.commandline-api
        CommandLine cl = new CommandLine(exe);
        // ruleid: team.java.audit.commandline-api
        cl.addArgument(file);
    }
}
