use mcp_sdk::transport::StdioTransport;
use tokio::process::Command;

async fn spawn() {
    let cmd = std::env::args().nth(1).unwrap();
    let _child = Command::new(cmd);
}
