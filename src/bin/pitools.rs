use anyhow::Result;
use pitools::server;
use std::str::FromStr;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    // let addr = "0.0.0.0:3000".parse().unwrap();
    // tracing::info!("Listening on address {:?}", addr);
    // server::Server::new().run(addr).await?;

    let server_mac_str = std::env::var("SERVER_MAC")?;
    let mac = pitools::wol::MacAddress::from_str(&server_mac_str).unwrap();
    pitools::wol::send_wol(mac).await?;

    Ok(())
}
