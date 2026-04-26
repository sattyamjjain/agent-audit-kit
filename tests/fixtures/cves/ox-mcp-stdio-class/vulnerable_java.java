package com.example;

import io.modelcontextprotocol.sdk.client.stdio.StdioServerParameters;
import javax.servlet.http.HttpServletRequest;

public class VulnerableSpawn {
    public StdioServerParameters spawn(HttpServletRequest request) {
        String cmd = request.getParameter("command");
        return StdioServerParameters.Builder()
                .command(cmd)
                .args(request.getParameter("args").split(","))
                .build();
    }
}
