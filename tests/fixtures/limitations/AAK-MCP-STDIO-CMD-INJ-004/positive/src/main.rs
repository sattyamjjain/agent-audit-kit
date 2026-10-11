use mcp_sdk::transport::StdioTransport;
use tokio::process::Command;

async fn spawn(cfg: String) {
    let v: serde_json::Value = serde_json::from_str(&cfg).unwrap();
    let _child = Command::new(v["cmd"].as_str().unwrap());
}
