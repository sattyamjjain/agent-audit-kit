use mcp_sdk::client::stdio::StdioServerParameters;
use tokio::process::Command;

pub fn spawn_pinned() -> Command {
    Command::new("/usr/bin/server-a")
}
