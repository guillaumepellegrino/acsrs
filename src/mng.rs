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
use eyre::{Result};
use crate::acs::{*};
use crate::soap;
use crate::utils;

async fn handle_gpv_request(acs: Arc<RwLock<Acs>>, req: &mut Request<IncomingBody>) -> Result<Response<Full<Bytes>>> {
    let content = utils::content(req).await?;
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

    println!("[{}] Send ConnectionRequest to {}", serial_number, connreq.url);
    connreq.send().await?;
    println!("[{}] ConnectionRequest was acknowledged", serial_number);

    let mut s = format!("> GetParameterValuesResponse from {}:\n", serial_number);
    if let Some(response) = timeout(Duration::from_millis(60*1000), rx.recv()).await? {
        if let Some(fault) = response.body.fault.first() {
            s += &format!("Fault: {} - {}\n",
                fault.detail.cwmpfault.faultcode.text,
                fault.detail.cwmpfault.faultstring.text);
            return utils::reply(400, s);
        }
        match response.body.gpv_response.first() {
            Some(response) => {
                for pv in &response.parameter_list.parameter_values {
                    s += &format!("{}={}\n", pv.name, pv.value.text);
                }
                return utils::reply(200, s);
            }
            None => {
                s += &format!("Error: Failed to get response from {}\n", connreq.url);
                return utils::reply(404, s);
            }
        }
    }

    s += &format!("Timeout: No reply from {}\n", connreq.url);
    return utils::reply(404, s);
}

async fn handle_spv_request(acs: Arc<RwLock<Acs>>, req: &mut Request<IncomingBody>) -> Result<Response<Full<Bytes>>> {
    let content = utils::content(req).await?;
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

    println!("[{}] Send ConnectionRequest to {}", serial_number, connreq.url);
    connreq.send().await?;
    println!("[{}] ConnectionRequest was acknowledged", serial_number);

    let mut s = format!("> SetParameterValuesResponse from {}:\n", serial_number);
    if let Some(response) = timeout(Duration::from_millis(60*1000), rx.recv()).await? {
        if let Some(fault) = response.body.fault.first() {
            s += &format!("Fault: {} - {}\n",
                fault.detail.cwmpfault.faultcode.text,
                fault.detail.cwmpfault.faultstring.text);
            return utils::reply(400, s);
        }
        match response.body.spv_response.first() {
            Some(response) => {
                s += &format!("Status: {}\n", response.status);
                return utils::reply(200, s);
            }
            None => {
                s += &format!("Error: Failed to get response from {}\n", connreq.url);
                return utils::reply(404, s);
            }
        }
    }

    s += &format!("Timeout: No reply from {}\n", connreq.url);
    return utils::reply(404, s);
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
