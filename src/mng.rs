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
use crate::acs::{*};
use crate::soap;
use crate::utils;

async fn cpe_transfer(acs: Arc<RwLock<Acs>>, serial_number: &str, request: soap::Envelope) -> Result<soap::Envelope> {
    // Get the CPE context from its serial number
    let acs = acs.read().await;
    let mut cpe = match &acs.cpe_list.get(serial_number) {
        Some(cpe) => cpe.write().await,
        None => {return Err(eyre!("CPE with SN:{} is not registered\n", serial_number));}
    };
    let connreq = cpe.connreq.clone();

    // Add a transfer to the CPE, here
    let mut transfer = Transfer::new();
    transfer.msg = request;
    let mut rx = transfer.rxchannel();
    cpe.transfers.push_back(transfer);

    // Unlock CPE and ACS
    drop(cpe);
    drop(acs);

    // Send the ConnectionRequest to CPE
    println!("[{}] Send ConnectionRequest to {}", serial_number, connreq.url);
    connreq.send().await?;
    println!("[{}] ConnectionRequest was acknowledged", serial_number);

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

async fn handle_gpv_request(acs: Arc<RwLock<Acs>>, req: &mut Request<IncomingBody>) -> Result<Response<Full<Bytes>>> {
    let content = utils::content(req).await?;
    let serial_number = utils::req_path(req, 2);
    let mut envelope = soap::Envelope::new(0);
    let gpv = envelope.add_gpv();
    for param in content.split(";") {
        gpv.push(&param);
    }
    let result = cpe_transfer(acs, &serial_number, envelope).await;
    soap_response(&result).await
}

async fn handle_spv_request(acs: Arc<RwLock<Acs>>, req: &mut Request<IncomingBody>) -> Result<Response<Full<Bytes>>> {
    let content = utils::content(req).await?;
    let serial_number = utils::req_path(req, 2);
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

async fn handle_list_request(acs: Arc<RwLock<Acs>>, _req: &mut Request<IncomingBody>) -> Result<Response<Full<Bytes>>> {
    let acs = acs.read().await;
    let mut s = format!("{}x Managed CPEs:\n", acs.cpe_list.len());

    for (sn, cpe) in &acs.cpe_list {
        let cpe = cpe.read().await;
        s += &format!("{} - {} - {} - {} \n", sn, cpe.connreq.url, cpe.connreq.username, cpe.connreq.password);
    }
    utils::reply(200, s)
}

async fn handle_stats_request(_acs: Arc<RwLock<Acs>>, _req: &mut Request<IncomingBody>) -> Result<Response<Full<Bytes>>> {
    let s = format!("Stats not implemented");
    utils::reply(200, s)
}

async fn handle_welcome_request(_acs: Arc<RwLock<Acs>>, _req: &mut Request<IncomingBody>) -> Result<Response<Full<Bytes>>> {
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

async fn handle_err404(_acs: Arc<RwLock<Acs>>, req: &mut Request<IncomingBody>) -> Result<Response<Full<Bytes>>> {
    let s = format!("Unknown request: {}\n", req.uri());
    utils::reply(404, s)
}

// TODO:
// - Check if a session is already opened before sending a ConnectionRequest.
// - Maintain the connection to CPE open as long as one management session is opened.
//
pub async fn handle_request(acs: Arc<RwLock<Acs>>, req: &mut Request<IncomingBody>) -> Result<Response<Full<Bytes>>> {
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
