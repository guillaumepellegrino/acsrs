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
use bytes::Bytes;
use http_body_util::{Full};
use tokio;
use tokio::sync::{RwLock};
use tokio::time::{Duration, timeout};
use hyper::{body::Incoming as IncomingBody, Request, Response};
use regex::Regex;
use eyre::{Result, eyre, WrapErr};
use serde::Deserialize;
use serde::Serialize;
use crate::acs::{*};
use crate::soap;
use crate::utils;

async fn cpe_transfer(acs: Arc<RwLock<Acs>>, serial_number: &str, request: soap::Envelope) -> Result<soap::Envelope> {
    // Get the CPE context from its serial number
    let cpe = match acs.read().await.cpe_list.get(serial_number) {
        Some(cpe) => cpe.clone(),
        None => {return Err(eyre!("CPE with SN:{} is not registered\n", serial_number));}
    };


    // Add a transfer to the CPE, here
    let controller = CPEController::new(cpe).await;
    let mut transfer = Transfer::new();
    transfer.msg = request;
    let mut rx = transfer.rxchannel();
    controller.add_transfer(transfer).await?;

    // Wait for our ACS server to get the transfer response
    let rx_future = timeout(Duration::from_millis(60*1000), rx.recv());
    let rx = rx_future.await
        .wrap_err_with(|| {format!("ACS server failed to get a response from CPE")})?;
    let response = match rx {
        Some(response) => response,
        None => {
            return Err(eyre!("ACS server failed to get a response from CPE"));
        }
    };

    Ok(response)
}

async fn soap_response(soap_result: &Result<soap::Envelope>) -> Result<Response<Full<Bytes>>> {
    match soap_result {
        Ok(envelope) => {
            let s = format!("> {:?}:\n{}\n", envelope.kind(), envelope);
            utils::reply(200, s)
        },
        Err(err) => {
            let s = format!("> Error:\n{:?}\n", err);
            utils::reply(400, s)
        },
    }
}

async fn handle_gpv_request(acs: Arc<RwLock<Acs>>, serial_number: &str, content: &str) -> Result<Response<Full<Bytes>>> {
    let mut envelope = soap::Envelope::new(0);
    let gpv = envelope.add_gpv();
    for param in content.split(";") {
        gpv.push(&param);
    }
    let result = cpe_transfer(acs, &serial_number, envelope).await;
    soap_response(&result).await
}

async fn handle_spv_request(acs: Arc<RwLock<Acs>>, serial_number: &str, content: &str) -> Result<Response<Full<Bytes>>> {
    let mut envelope = soap::Envelope::new(0);
    let spv = envelope.add_spv(1);
    let re = Regex::new(r"(\w|.+)\s*<(\w+)>\s*=\s*(\w+)").unwrap();
    for param in content.split(";") {
        let captures = re.captures(param).unwrap();
        let key = captures.get(1).unwrap().as_str();
        let base_type = captures.get(2).unwrap().as_str();
        let xsd_type = format!("xsd:{}", base_type);
        let value = captures.get(3).unwrap().as_str();
        //println!("SPV({},{},{})", key, xsd_type, value);
        spv.push(soap::ParameterValue::new(key, &xsd_type, value));
    }
    let result = cpe_transfer(acs, &serial_number, envelope).await;
    soap_response(&result).await
}

async fn handle_connect_request(acs: Arc<RwLock<Acs>>, serial_number: &str, content: &str) -> Result<Response<Full<Bytes>>> {
    /*
    struct TR069Session {
        // Reference to the associated CPE
        cpe: Option<Arc<RwLock<CPE>>>,
        transfers: mpmc::Receiver<Transfer>,
    }

    struct CPEController {
        cpe: Option<Arc<RwLock<CPE>>>,
        transfers_tx: mpmc::Sender<Transfer>,
    }

    struct CPE {
        tr069_session_refcount: Arc<AtomicI32>,
        cpe_controllers_refcount: Arc<AtomicI32>,
        transfers_tx: mpmc::Sender<Transfer>,
        transfers_rx: mpmc::Receiver<Transfer>,
    }

    struct ManagementSession {
        // List of CPEController in use by the ManagementSession.
        cpe_list: HashMap<String, CPEController>,
    }

    impl CPE {
        fn open_session() => CPEController;
    }
    impl CPEController {
        fn add_transfer(msg: soap::Body) -> Result<mpsc::Receiver<soap::Body>>;
    }


    mng::Session.init() ==> CPE.open_session()->CPEController

    mng::Session.add_transfer() => CPEController.add_transfer();
        if !session {self.sendConnRequest()}
        
    }

    */

    utils::reply(400, String::from("not implemented"))
}

async fn handle_download_request(acs: Arc<RwLock<Acs>>, serial_number: &str, content: &str) -> Result<Response<Full<Bytes>>> {
    #[derive(Debug, PartialEq, Default, Deserialize, Serialize)]
    struct Download {
        #[serde(default)]
        command_key: String,

        #[serde(default)]
        file_type: String,

        #[serde(default)]
        url: String,

        #[serde(default)]
        username: String,

        #[serde(default)]
        password: String,

        #[serde(default)]
        file_size: i64,

        #[serde(default)]
        target_file_name: String,

        #[serde(default)]
        delay_seconds: i32,

        #[serde(default)]
        success_url: String,

        #[serde(default)]
        failure_url: String,
    }
    let download: Download = serde_qs::from_str(&content)?;

    let mut envelope = soap::Envelope::new(0);
    let soap_download = envelope.add_download();
    soap_download
        .set_command_key(&download.command_key)
        .set_file_type(&download.file_type)
        .set_url(&download.url)
        .set_username(&download.username)
        .set_password(&download.password)
        .set_file_size(download.file_size)
        .set_target_file_name(&download.target_file_name)
        .set_delay_seconds(download.delay_seconds)
        .set_success_url(&download.success_url)
        .set_failure_url(&download.failure_url);

    let result = cpe_transfer(acs, &serial_number, envelope).await;
    soap_response(&result).await
}

async fn handle_list_request(acs: Arc<RwLock<Acs>>) -> Result<Response<Full<Bytes>>> {
    let acs = acs.read().await;
    let mut s = format!("{}x Managed CPEs:\n", acs.cpe_list.len());

    for (sn, cpe) in &acs.cpe_list {
        let cpe = cpe.read().await;
        s += &format!("{} - {} - {} - {} \n", sn, cpe.connreq.url, cpe.connreq.username, cpe.connreq.password);
    }
    utils::reply(200, s)
}

async fn handle_stats_request() -> Result<Response<Full<Bytes>>> {
    let s = format!("Stats not implemented");
    utils::reply(200, s)
}

async fn handle_welcome_request() -> Result<Response<Full<Bytes>>> {
    let mut s = format!("Welcome on ACS Server\n");
    s += "Usage:\n";
    s += "- List managed cpes by this acs\n";
    s += "curl 127.0.0.1:8000/list\n\n";
    s += "- Send a GetParameterValues to the specified cpe\n";
    s += "curl 127.0.0.1:8000/gpv/{cpe_serial_numer} -d device.managementserver.\n\n";
    s += "- Send a SetParameterValues to the specified cpe\n";
    s += "curl 127.0.0.1:8000/spv/{cpe_serial_numer} -d \"device.wifi.neighboringwifidiagnostic.diagnosticsstate<string>=requested\"\n\n";
    s += "- Send a GetParameterValues to the specified CPE, requesting multiple objects\n";
    s += "curl 127.0.0.1:8000/gpv/{CPE_SERIAL_NUMER} -d Device.ManagementServer.;Device.Time.\n\n";

    utils::reply(200, s)
}

async fn handle_err404(req: &mut Request<IncomingBody>) -> Result<Response<Full<Bytes>>> {
    let s = format!("Unknown request: {}\n", req.uri());
    utils::reply(404, s)
}

// TODO:
// - Check if a session is already opened before sending a ConnectionRequest.
// - Maintain the connection to CPE open as long as one management session is opened.
//
pub async fn handle_request(acs: Arc<RwLock<Acs>>, req: &mut Request<IncomingBody>) -> Result<Response<Full<Bytes>>> {
    let command = utils::req_path(&req, 1);
    let serial_number = utils::req_path(&req, 2);
    let content = utils::content(req).await?;
    let reply = match command.as_str() {
        "gpv"       => handle_gpv_request(acs, &serial_number, &content).await,
        "spv"       => handle_spv_request(acs, &serial_number, &content).await,
        "connect"   => handle_connect_request(acs, &serial_number, &content).await,
        "download"  => handle_download_request(acs, &serial_number, &content).await,
        "list"      => handle_list_request(acs).await,
        "stats"     => handle_stats_request().await,
        ""          => handle_welcome_request().await,
        _           => handle_err404(req).await,
    };

    match reply {
        Ok(reply) => Ok(reply),
        Err(error) => utils::reply_error(error),
    }
}

#[tokio::test]
async fn test_mpmc() {
    let (tx, rx) = flume::unbounded();
    let rx2 = rx.clone();

    tx.send_async(42).await.unwrap();
    tx.send_async(43).await.unwrap();

    assert_eq!(rx.recv_async().await.unwrap(), 42);

    tokio::spawn(async move {
        assert_eq!(rx2.recv_async().await.unwrap(), 43);
        assert_eq!(rx2.recv_async().await.unwrap(), 44);
    });

    tx.send_async(44).await.unwrap();
}
