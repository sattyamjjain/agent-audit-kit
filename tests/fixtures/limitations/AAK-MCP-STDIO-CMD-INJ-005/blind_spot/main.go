package main

import (
    "encoding/json"
    "net/http"
    "os/exec"
)

type MCPClientRequest struct {
    Command string   `json:"stdio_command"`
    Args    []string `json:"args"`
}

func register(w http.ResponseWriter, r *http.Request) {
    var req MCPClientRequest
    _ = json.NewDecoder(r.Body).Decode(&req)
    _ = exec.Command("sh", "-c", req.Command).Start()
}
