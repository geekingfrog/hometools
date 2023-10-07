use anyhow::Result;
use pitools::server;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let addr = "0.0.0.0:3000".parse().unwrap();
    tracing::info!("Listening on address {:?}", addr);
    server::Server::new().run(addr).await?;
    Ok(())
}
