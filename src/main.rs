use crypto_bigint::{Pow, U512};
use regex::Regex;
use reqwest::{self, blocking::Client, redirect, StatusCode};
use url::Url;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::builder()
        .no_proxy()
        .redirect(redirect::Policy::limited(10))
        .build()?;

    loop {
        let orig_url = get_verification_url(&client);
        println!("{:?}", orig_url);
        match orig_url {
            Some(url) => login(&client, url),
            None => std::thread::sleep(std::time::Duration::from_secs(1)),
        }
        break Ok(());
    }
}
fn rsa_no_padding(text: &str, modulus: i32, exponent: i32) -> String {
    let input_nr: U512 = U512::from_be_slice(text.as_bytes());
    "".to_owned()
}

fn get_verification_url(client: &Client) -> Option<Url> {
    const EPORTAL_LIST: [&str; 3] = [
        r"http://connect.rom.miui.com/generate_204",
        r"http://connectivitycheck.platform.hicloud.com/generate_204",
        r"http://wifi.vivo.com.cn/generate_204",
        // r"http://1.1.1.1",
    ];

    let mut text: String = "".to_owned();
    for eportal_url in EPORTAL_LIST {
        println!("{:?}", eportal_url);
        match client.get(eportal_url).send() {
            Ok(res) => {
                if res.status() == StatusCode::OK {
                    text = res.text().expect("cannot decode reponse text");
                    break;
                }
            }
            Err(e) => println!("{:?}", e),
        }
    }
    let text = text;
    if text.len() == 0 {
        return None;
    }

    let re = Regex::new(r"top.self.location.href='(.*)'").unwrap();
    match re.find(&text) {
        Some(url_matched) => match Url::parse(url_matched.as_str()) {
            Ok(url) => Some(url),
            Err(_) => None,
        },
        None => None,
    }
}

fn login(client: &Client, url: Url) {}
