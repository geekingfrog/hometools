use std::net::Ipv4Addr;

use tokio::net::UdpSocket;

#[derive(Debug)]
pub struct MacAddress([u8; 6]);

#[derive(Debug)]
pub struct ParseMacError;

impl std::str::FromStr for MacAddress {
    type Err = ParseMacError;

    /// given a 6 bytes mac address in hex form like MM:MM:MM:SS:SS:SS parses it
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let frags = s
            .split(':')
            .map(|frag| {
                hex::decode(frag).map_err(|_| ParseMacError).and_then(|bs| {
                    if bs.len() != 1 {
                        Err(ParseMacError)
                    } else {
                        Ok(bs[0])
                    }
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        if frags.len() != 6 {
            return Err(ParseMacError);
        }

        let bs = [frags[0], frags[1], frags[2], frags[3], frags[4], frags[5]];
        Ok(MacAddress(bs))
    }
}

pub async fn send_wol(mac: &MacAddress) -> anyhow::Result<()> {
    let sock = UdpSocket::bind("0.0.0.0:0").await?;
    sock.set_broadcast(true)?;
    let mut magic_packet = [0xFF; 6 + 6 * 16];
    for i in 0..16 {
        let offset = 6 + i * 6;
        magic_packet[offset..offset + 6].copy_from_slice(&mac.0);
    }

    sock.connect((Ipv4Addr::BROADCAST, 7)).await?;
    sock.send(&magic_packet).await?;

    Ok(())
}
