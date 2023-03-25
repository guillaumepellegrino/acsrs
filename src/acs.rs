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
use bytes::Bytes;
use http_body_util::Full;
use tokio;
use tokio::sync::{RwLock, mpsc};
use hyper::{body::Incoming as IncomingBody, Request, Response};
use rand::{thread_rng, Rng};
use rand::distributions::Alphanumeric;
use base64::Engine;
use crate::soap;
use crate::utils;
use crate::session::Session;

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
    pub basicauth: String,
    pub cpe_list: HashMap<String, Arc<RwLock<CPE>>>,
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
    pub fn new(username: &str, password: &str) -> Self {
        let mut acs = Self::default();
        acs.basicauth = Self::basicauth(username, password);
        acs
    }

    fn basicauth(username: &str, password: &str) -> String {
        let token = format!("{}:{}", username, password);
        let token64 = base64::engine::general_purpose::STANDARD.encode(&token);
        format!("Basic {}", token64)
    }
}

