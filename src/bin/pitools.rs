use anyhow::Result;
use pitools::server;

// use password_hash::{rand_core::OsRng, PasswordHasher, SaltString};
// use scrypt::Scrypt;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let addr = "0.0.0.0:3000".parse().unwrap();
    let server = server::Server::new().await?;
    server.run(addr).await?;

    // let b64_salt = "deadbeefdeadbeef";
    // let salt = SaltString::from_b64(b64_salt)?;
    // let hash = Scrypt.hash_password(b"hunter2", &salt)?;
    // println!("{}", hash);

    Ok(())
}
