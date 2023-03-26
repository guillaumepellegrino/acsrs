/*
 * Copyright (C) 2023 Guillaume Pellegrino
 * This file is part of acsrs <https://github.com/guillaumepellegrino/acsrs>.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
use std::sync::{Arc};
use std::collections::VecDeque;
use std::collections::HashMap;
use tokio;
use tokio::sync::{RwLock, mpsc};
use rand::{thread_rng, Rng};
use rand::distributions::Alphanumeric;
use base64::Engine;
use crate::soap;
use crate::db;


#[derive(Debug)]
pub enum Error {
    ConnectionRequestAuthenticationFailed,
}

#[derive(Clone)]
pub struct Connreq {
    pub url: String,
    pub username: String,
    pub password: String,
}

pub struct Transfer {
    pub msg: soap::Envelope,
    pub observer: Option<mpsc::Sender<soap::Envelope>>,
}

#[derive(Default)]
pub struct CPE {
    pub device_id: soap::DeviceId,
    pub connreq: Connreq,
    pub transfers: VecDeque<Transfer>,
}

#[derive(Default)]
pub struct Acs {
    pub username: String,
    pub password: String,
    pub basicauth: String,
    pub cpe_list: HashMap<String, Arc<RwLock<CPE>>>,
    savefile: std::path::PathBuf,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ACS Error: {:?}\n", self)
    }
}
impl std::error::Error for Error {}

impl Transfer {
    pub fn new() -> Self {
        Self {
            msg: soap::Envelope::new(1),
            observer: None,
        }
    }

    pub fn rxchannel(self: &mut Self) -> mpsc::Receiver<soap::Envelope> {
        let (tx, rx) = mpsc::channel(1);
        self.observer = Some(tx);
        rx
    }
}

impl Default for Connreq {
    fn default() -> Self {
        Self {
            url: String::from(""),
            username: String::from("acsrs"),
            password: thread_rng()
                .sample_iter(&Alphanumeric)
                .take(30)
                .map(char::from)
                .collect(),
        }
    }
}

impl Connreq {
    pub async fn send(self: &Self) -> Result<(), Box<dyn std::error::Error>> {
        let client = reqwest::Client::new();

        // Step 1:  Get the auth header
        let res = client.get(&self.url).send().await?;
        let headers = res.headers();
        let wwwauth = headers["www-authenticate"].to_str()?;

        // Step 2:  Given the auth header, sign the digest for the real req.
        let context = digest_auth::AuthContext::new(&self.username, &self.password, "/");
        let mut prompt = digest_auth::parse(wwwauth)?;
        let answer = prompt.respond(&context)?.to_header_string();
        let response = client.get(&self.url).header("Authorization", answer).send().await?;

        match response.status() {
            reqwest::StatusCode::OK => Ok(()),
            _ => Err(Box::new(Error::ConnectionRequestAuthenticationFailed)),
        }
    }
}

impl Acs {
    pub fn new(username: &str, password: &str, savefile: &std::path::Path) -> Self {
        let mut acs = Self::default();
        acs.username = String::from(username);
        acs.password = String::from(password);
        acs.basicauth = Self::basicauth(username, password);
        acs.savefile = savefile.to_path_buf();
        acs
    }

    fn basicauth(username: &str, password: &str) -> String {
        let token = format!("{}:{}", username, password);
        let token64 = base64::engine::general_purpose::STANDARD.encode(&token);
        format!("Basic {}", token64)
    }

    pub async fn save_at(self: &Self, path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
        println!("Save ACS config at {:?}", path);

        let mut db = db::Acs::default();
        db.username = self.username.clone();
        db.password = self.password.clone();

        for (sn, cpe) in &self.cpe_list {
            let cpe = cpe.read().await;
            let elem = db::CPE {
                serial_number: sn.clone(),
                url: cpe.connreq.url.clone(),
                username: cpe.connreq.username.clone(),
                password: cpe.connreq.password.clone(),
            };
            db.cpe.push(elem);
        }

        db.save(path)
    }

    pub async fn save(self: &Self) -> Result<(), Box<dyn std::error::Error>> {
        self.save_at(&self.savefile).await
    }

    pub async fn restore(path: &std::path::Path) -> Result<Self, Box<dyn std::error::Error>> {
        let db = db::Acs::restore(path)?;
        let mut acs = Self::default();
        acs.username = db.username.clone();
        acs.password = db.password.clone();
        acs.basicauth = Acs::basicauth(&acs.username, &acs.password);

        for elem in &db.cpe {
            let mut cpe = CPE::default();
            cpe.device_id.serial_number = elem.serial_number.clone();
            cpe.connreq.url = elem.url.clone();
            cpe.connreq.username = elem.username.clone();
            cpe.connreq.password = elem.password.clone();
            acs.cpe_list.insert(elem.serial_number.clone(), Arc::new(RwLock::new(cpe)));
        }

        Ok(acs)
    }

    pub async fn print_config(self: &Self) {
        let server = "http://ifconfig.me";
        let response = match reqwest::get(server).await {
            Ok(value) => value,
            Err(e) => {
                println!("Failed to get ACS URL from {}: {:?}", server, e);
                return;
            }
        };
        let ipaddress = match response.text().await {
            Ok(value) => value,
            Err(e) => {
                println!("Failed to get ACS URL from {}: {:?}", server, e);
                return;
            }
        };

        println!("");
        println!("Please ensure your CPEs are configured with:");
        println!("Device.ManagementServer.URL=http://{}:8443/cwmpWeb/CPEMgt", ipaddress);
        println!("Device.ManagementServer.Username={}", self.username);
        println!("Device.ManagementServer.Password={}", self.password);
        println!("");
    }
}

#[tokio::test]
async fn test_acs_save_restore() {
    let savefile = std::path::PathBuf::from("/tmp/acs.toml");
    let username = "toto";
    let password = "Martin";
    let mut acs = Acs::new(username, password);

    let mut cpe1 = CPE::default();
    cpe1.connreq.url = String::from("http://192.168.1.X:7547/CPE1");
    acs.cpe_list.insert("CPE1_SN".to_string(), Arc::new(RwLock::new(cpe1)));

    let mut cpe2 = CPE::default();
    cpe2.connreq.url = String::from("http://192.168.1.X:7547/CPE2");
    acs.cpe_list.insert("CPE2_SN".to_string(), Arc::new(RwLock::new(cpe2)));

    acs.save_at(&savefile).await.unwrap();

    let restored = Acs::restore(&savefile).await.unwrap();
    assert_eq!(&restored.username, &acs.username);
    assert_eq!(&restored.password, &acs.password);
    assert_eq!(&restored.basicauth, &acs.basicauth);
    assert_eq!(&restored.cpe_list["CPE1_SN"].read().await.connreq.url, "http://192.168.1.X:7547/CPE1");
    assert_eq!(&restored.cpe_list["CPE2_SN"].read().await.connreq.url, "http://192.168.1.X:7547/CPE2");
}
