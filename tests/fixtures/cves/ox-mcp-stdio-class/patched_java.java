package com.example;

import io.modelcontextprotocol.sdk.client.stdio.StdioServerParameters;

public class PatchedSpawn {
    private static final java.util.Map<String, String> ALLOWED =
        java.util.Map.of("server-a", "/usr/bin/server-a");

    public StdioServerParameters spawn(String name) {
        String cmd = ALLOWED.get(name);
        if (cmd == null) throw new IllegalArgumentException("not allowed");
        return StdioServerParameters.Builder()
                .command(cmd)
                .args(new String[]{})
                .build();
    }
}
