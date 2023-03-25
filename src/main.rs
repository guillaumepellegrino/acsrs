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
use std::net::SocketAddr;
use std::collections::VecDeque;
use std::collections::HashMap;
use bytes::Bytes;
use http_body_util::Full;
use http_body_util::BodyExt;
use tokio;
use tokio::sync::{RwLock, mpsc};
use tokio::time::{Duration, timeout};
use tokio::net::TcpListener;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{body::Incoming as IncomingBody, Request, Response};
use rand::{thread_rng, Rng};
use rand::distributions::Alphanumeric;
use regex::Regex;
use base64::Engine;

mod soap;
mod utils;

#[derive(Debug)]
enum Error {
    ConnectionRequestAuthenticationFailed,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ACS Error: {:?}\n", self)
    }
}
impl std::error::Error for Error {}

struct Transfer {
    msg: soap::Envelope,
    observer: Option<mpsc::Sender<soap::Envelope>>,
}

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

#[derive(Clone)]
struct Connreq {
    url: String,
    username: String,
    password: String,
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

#[derive(Default)]
struct CPE {
    device_id: soap::DeviceId,
    connreq: Connreq,
    transfers: VecDeque<Transfer>,
}

#[derive(Default)]
struct Acs {
    basicauth: String,
    cpe_list: HashMap<String, Arc<RwLock<CPE>>>,
}

impl Acs {
    fn new(username: &str, password: &str) -> Self {
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

struct Session {
    acs: Arc<RwLock<Acs>>,
    cpe: Option<Arc<RwLock<CPE>>>,
    observer: Option<mpsc::Sender<soap::Envelope>>,
    id: u32,
}

impl Session {
    pub fn new(acs: Arc<RwLock<Acs>>) -> Self {
        Session {
            acs: acs.clone(),
            cpe: None,
            observer: None,
            id: 0,
        }
    }

    async fn cpe_handle_inform(self: &mut Self, inform: &soap::Inform) {
        let connreq_url = match inform.parameter_list.get_value("Device.ManagementServer.ConnectionRequestURL") {
            Some(value) => value,
            None => {return;},
        };

        let mut acs = self.acs.write().await;
        let cpelock = acs.cpe_list.entry(inform.device_id.serial_number.clone()).or_default();
        self.cpe = Some(cpelock.clone());
        let mut cpe = cpelock.write().await;
        cpe.device_id = inform.device_id.clone();
        if cpe.connreq.url != connreq_url {
            println!("connreq.url is not configred: Configure ConnectionRequest");
            cpe.connreq.url = String::from(connreq_url);

            // Push a tranfer to configure ConnectionRequest with an SPV
            let mut transfer = Transfer::new();
            let spv = transfer.msg.add_spv(1);
            spv.push(soap::ParameterValue::new(
                "Device.ManagementServer.ConnectionRequestUsername", "xsd:string", &cpe.connreq.username));
            spv.push(soap::ParameterValue::new(
                "Device.ManagementServer.ConnectionRequestPassword", "xsd:string", &cpe.connreq.password));
            cpe.transfers.push_back(transfer);
        }
    }

    async fn cpe_check_transfers(self: &mut Self) -> Result<Response<Full<Bytes>>, Box<dyn std::error::Error>> {
        let mut cpe = match &self.cpe {
            Some(cpe) => cpe.write().await,
            None => {
                println!("Unknown CPE: Reply with no content");
                return utils::reply(204, String::from(""));
            }
        };

        let mut transfer = match cpe.transfers.pop_front() {
            Some(transfer) => transfer,
            None => {
                println!("No pending transfer for CPE: Reply with no content");
                return utils::reply(204, String::from(""));
            }
        };
        transfer.msg.header.id.text = self.id;
        self.observer = transfer.observer;
        drop(cpe);

        println!("Transfer pending message");
        return utils::reply_xml(&transfer.msg);
    }

    async fn content(req: &mut Request<IncomingBody>) -> Result<String, Box<dyn std::error::Error>> {
        let body = req.collect().await?.to_bytes();
        Ok(String::from_utf8(body.to_vec())?)
    }

    async fn handle_cpe_request(self: &mut Self, req: &mut Request<IncomingBody>) -> Result<Response<Full<Bytes>>, Box<dyn std::error::Error>> {
        println!("Received from CPE:");
        println!("  Headers: {:?}", req.headers());

        let content = Self::content(req).await?;
        //println!("  Content: [\n{}\n]", content);

        //  The CPE has nothing to tell us: We may ask for a new Transfer
        if content.is_empty() {
            return self.cpe_check_transfers().await;
        }

        // Try to parse XML content
        let envelope: soap::Envelope = match quick_xml::de::from_str(&content) {
            Ok(value) => value,
            Err(e) => {
                println!("Failed to parse XML: {:?}", e);
                println!("Content: [\n{}\n]\nContent End", content);
                return utils::reply(204, String::from(""));
            },
        };

        // Process message sent by CPE
        if let Some(inform) = envelope.inform() {
            println!("Inform received from {}", inform.device_id.serial_number);
            println!("Session ID: {}", envelope.id());
            self.id = envelope.id();

            for event in &inform.event.event_struct {
                println!("Event: {}", event.event_code);
            }
            self.cpe_handle_inform(&inform).await;

            let mut response = soap::Envelope::new(envelope.id());
            response.add_inform_response();
            return utils::reply_xml(&response);
        }
        else if let Some(_gpv_response) = envelope.body.gpv_response.first() {
            println!("GPV Response");
        }
        else if let Some(spv_response) = envelope.body.spv_response.first() {
            println!("SPV Response: {}", spv_response.status);
        }
        else {
            println!("Unknown SOAP/xml request: {}", content);
            return utils::reply(204, String::from(""));
        }

        // If someone if observing the current Transfer,
        // we forward the CPE response to him.
        if let Some(observer) = self.observer.as_mut() {
            if let Err(err) = observer.send(envelope).await {
                println!("Failed to forward Response: {:?}", err);
            }
            self.observer = None;
        }

        // We may ask for a new Transfer
        return self.cpe_check_transfers().await;
    }

    async fn check_cpe_authorization(self: &mut Self, req: &mut Request<IncomingBody>) -> Result<Response<Full<Bytes>>, Box<dyn std::error::Error>> {

        match req.headers().get("authorization") {
            Some(wwwauth) => {
                let wwwauth = wwwauth.to_str()?;
                if wwwauth == &self.acs.read().await.basicauth {
                    self.handle_cpe_request(req).await
                }
                else {
                    utils::reply(403, String::from("Forbidden\n"))
                }
            }
            None => {
                println!("auth required!");
                let response = String::from("Authorization required\n");
                let builder = Response::builder()
                    .header("User-Agent", "acsrs")
                    .header("WWW-Authenticate", "Basic realm=\"acrsrs world\"")
                    .status(401);
                Ok(builder.body(Full::new(Bytes::from(response)))?)
            }
        }
    }


    async fn handle(self: &mut Self, req: &mut Request<IncomingBody>) -> Result<Response<Full<Bytes>>, hyper::Error> {
        let reply = match req.uri().path() {
            "/cwmpWeb/CPEMgt" => self.check_cpe_authorization(req).await,
            _                 => utils::reply(403, String::from("Forbidden\n")),
        };

        match reply {
            Ok(reply)  => Ok(reply),
            Err(error) => utils::reply_error(error),
        }
    }
}

async fn handle_gpv_request(acs: Arc<RwLock<Acs>>, req: &mut Request<IncomingBody>) -> Result<Response<Full<Bytes>>, Box<dyn std::error::Error>> {
    let content = Session::content(req).await?;
    let serial_number = utils::req_path(req, 2);
    let acs = acs.read().await;
    let mut cpe = match &acs.cpe_list.get(&serial_number) {
        Some(cpe) => cpe.write().await,
        None => {return utils::reply(404, format!("CPE with SN:{} is not registered\n", serial_number));}
    };
    let connreq = cpe.connreq.clone();

    // Add a transfer, here
    let mut transfer = Transfer::new();
    let mut rx = transfer.rxchannel();
    let gpv = transfer.msg.add_gpv();
    for param in content.split(";") {
        gpv.push(&param);
    }
    cpe.transfers.push_back(transfer);
    drop(cpe);
    drop(acs);

    connreq.send().await?;
    if let Some(response) = timeout(Duration::from_millis(10*1000), rx.recv()).await? {
        match response.body.gpv_response.first() {
            Some(response) => {
                let mut s = format!("> GetParameterValuesResponse from {}:\n", serial_number);
                for pv in &response.parameter_list.parameter_values {
                    s += &format!("{}={}\n", pv.name, pv.value.text);
                }
                return utils::reply(200, s);
            }
            None => {
                return utils::reply(404, format!("Bad response from {}\n", serial_number));
            }
        }
    }
    return utils::reply(404, format!("GPV Timeout for {}: {}\n", serial_number, connreq.url));
}

async fn handle_spv_request(acs: Arc<RwLock<Acs>>, req: &mut Request<IncomingBody>) -> Result<Response<Full<Bytes>>, Box<dyn std::error::Error>> {
    let content = Session::content(req).await?;
    let serial_number = utils::req_path(req, 2);
    let acs = acs.read().await;
    let mut cpe = match &acs.cpe_list.get(&serial_number) {
        Some(cpe) => cpe.write().await,
        None => {return utils::reply(404, format!("CPE with SN:{} is not registered\n", serial_number));}
    };
    let connreq = cpe.connreq.clone();

    // Add a transfer, here
    let mut transfer = Transfer::new();
    let mut rx = transfer.rxchannel();
    let spv = transfer.msg.add_spv(1);
    let re = Regex::new(r"(\w|.+)\s*<(\w+)>\s*=\s*(\w+)").unwrap();
    for param in content.split(";") {
        let captures = re.captures(param).unwrap();
        let key = captures.get(1).unwrap().as_str();
        let base_type = captures.get(2).unwrap().as_str();
        let xsd_type = format!("xsd:{}", base_type);
        let value = captures.get(3).unwrap().as_str();
        println!("SPV({},{},{})", key, xsd_type, value);
        spv.push(soap::ParameterValue::new(key, &xsd_type, value));
    }

    cpe.transfers.push_back(transfer);
    drop(cpe);
    drop(acs);

    connreq.send().await?;
    if let Some(response) = timeout(Duration::from_millis(10*1000), rx.recv()).await? {
        match response.body.spv_response.first() {
            Some(response) => {
                let mut s = format!("> SetParameterValuesResponse from {}:\n", serial_number);
                s += &format!("Status: {}", response.status);
                return utils::reply(200, s);
            }
            None => {
                return utils::reply(404, format!("Bad response from {}\n", serial_number));
            }
        }
    }
    return utils::reply(404, format!("SPV Timeout for {}: {}\n", serial_number, connreq.url));
}

async fn handle_list_request(acs: Arc<RwLock<Acs>>, _req: &mut Request<IncomingBody>) -> Result<Response<Full<Bytes>>, Box<dyn std::error::Error>> {
    let acs = acs.read().await;
    let mut s = format!("{}x Managed CPEs:\n", acs.cpe_list.len());

    for (sn, cpe) in &acs.cpe_list {
        let cpe = cpe.read().await;
        s += &format!("{} - {} - {} - {} \n", sn, cpe.connreq.url, cpe.connreq.username, cpe.connreq.password);
    }
    utils::reply(200, s)
}

async fn handle_stats_request(_acs: Arc<RwLock<Acs>>, _req: &mut Request<IncomingBody>) -> Result<Response<Full<Bytes>>, Box<dyn std::error::Error>> {
    let s = format!("Stats not implemented");
    utils::reply(200, s)
}

async fn handle_welcome_request(_acs: Arc<RwLock<Acs>>, _req: &mut Request<IncomingBody>) -> Result<Response<Full<Bytes>>, Box<dyn std::error::Error>> {
    let s = format!("Welcome on ACS Server\n");
    utils::reply(200, s)
}

async fn handle_err404(_acs: Arc<RwLock<Acs>>, req: &mut Request<IncomingBody>) -> Result<Response<Full<Bytes>>, Box<dyn std::error::Error>> {
    let s = format!("Unknown request: {}\n", req.uri());
    utils::reply(404, s)
}


async fn handle_mng_request(acs: Arc<RwLock<Acs>>, req: &mut Request<IncomingBody>) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let reply = match utils::req_path(&req, 1).as_str() {
        "gpv"   => handle_gpv_request(acs, req).await,
        "spv"   => handle_spv_request(acs, req).await,
        "list"  => handle_list_request(acs, req).await,
        "stats" => handle_stats_request(acs, req).await,
        ""      => handle_welcome_request(acs, req).await,
        _        => handle_err404(acs, req).await,
    };

    match reply {
        Ok(reply) => Ok(reply),
        Err(error) => utils::reply_error(error),
    }
}

#[tokio::main]
async fn main() {
    let username = match std::env::var("ACS_USERNAME") {
        Ok(value) => value,
        Err(_) => {
            println!("Please provide ACS_USERNAME and ACS_PASSWORD as env variables");
            return;
        }
    };
    let password = match std::env::var("ACS_PASSWORD") {
        Ok(value) => value,
        Err(_) => {
            println!("Please provide ACS_USERNAME and ACS_PASSWORD as env variables");
            return;
        }
    };

    let cpe_acs = Arc::new(RwLock::new(Acs::new(&username, &password)));
    let cpe_addr: SocketAddr = ([0, 0, 0, 0], 8443).into();
    let cpe_listener = TcpListener::bind(cpe_addr).await.unwrap();

    let mng_acs = cpe_acs.clone();
    let mng_addr: SocketAddr = ([127, 0, 0, 1], 8080).into();
    let mng_listener = TcpListener::bind(mng_addr).await.unwrap();

    println!("ACS listening on {:?}", cpe_addr);
    println!("Management server listening on {:?}", mng_addr);

    let cpe_srv = async move {
        loop {
            let (stream, _) = cpe_listener.accept().await.unwrap();
            let acs = cpe_acs.clone();
            tokio::task::spawn(async move {
                let session = Arc::new(RwLock::new(Session::new(acs)));
                let service = |mut req: Request<hyper::body::Incoming>| {
                    let session = session.clone();
                    return async move {
                        let mut session = session.write().await;
                        return session.handle(&mut req).await;
                    };
                };
                if let Err(err) = http1::Builder::new()
                    .serve_connection(stream, service_fn(service))
                    .await
                {
                    println!("Failed to serve connection: {:?}", err);
                }
            });
        }
    };

    let mng_srv = async move {
        loop {
            let (stream, _) = mng_listener.accept().await.unwrap();
            let acs = mng_acs.clone();
            tokio::task::spawn(async move {
                let service = |mut req: Request<hyper::body::Incoming>| {
                    let acs = acs.clone();
                    return async move {
                        return handle_mng_request(acs, &mut req).await;
                    };
                };
                if let Err(err) = http1::Builder::new()
                    .serve_connection(stream, service_fn(service))
                    .await
                {
                    println!("Failed to serve connection: {:?}", err);
                }
            });
        }
    };

    futures::future::join(cpe_srv, mng_srv).await;
}
