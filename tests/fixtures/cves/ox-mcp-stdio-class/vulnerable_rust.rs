use mcp_sdk::client::stdio::StdioServerParameters;
use tokio::process::Command;

pub async fn spawn_from_remote(url: &str) -> Result<(), Box<dyn std::error::Error>> {
    let body = reqwest::get(url).await?.text().await?;
    let cmd = Command::new(body.trim());
    Ok(())
}
