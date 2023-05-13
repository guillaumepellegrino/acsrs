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
use crate::acs::*;
use crate::api;
use crate::soap;
use crate::utils;
use bytes::Bytes;
use eyre::{eyre, Result, WrapErr};
use http_body_util::Full;
use hyper::{body::Incoming as IncomingBody, Request, Response};
use regex::Regex;
use serde::Deserialize;
use serde::Serialize;
use std::collections::hash_map::Entry::{Occupied, Vacant};
use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;
use tokio::time::{timeout, Duration};

pub struct ManagementSession {
    acs: Arc<RwLock<Acs>>,

    // CPEController used during the HTTP ManagementSession are stored in a HashMap
    // As long as the HTTP ManagementSession is alive the associated TR-069 sessions are kept alive as well.
    //
    // This is done to implement a fast and reactive cli. The HTTPs connection does not need to be
    // reestablished at each cli commands.
    controller_list: HashMap<String, CPEController>,
}

impl ManagementSession {
    pub fn new(acs: Arc<RwLock<Acs>>) -> Self {
        Self {
            acs,
            controller_list: HashMap::<String, CPEController>::new(),
        }
    }

    async fn cpe_transfer(
        &mut self,
        serial_number: &str,
        request: soap::Envelope,
    ) -> Result<soap::Envelope> {
        // Create a new transfer for the CPE
        let mut transfer = Transfer::new();
        transfer.msg = request;
        let mut rx = transfer.rxchannel();

        // Get or add a CPE Controller
        // and then add the transfer to it.
        let entry = self.controller_list.entry(String::from(serial_number));
        match entry {
            Occupied(o) => {
                let controller = o.get();
                controller.add_transfer(transfer).await?;
            }
            Vacant(v) => {
                // Get the CPE context from its serial number
                let cpe = match self.acs.read().await.cpe_list.get(serial_number) {
                    Some(cpe) => cpe.clone(),
                    None => {
                        return Err(eyre!("CPE with SN:{} is not registered\n", serial_number));
                    }
                };
                let controller = v.insert(CPEController::new(cpe.clone()).await);
                controller.add_transfer(transfer).await?;
            }
        };

        // Wait for our ACS server to get the transfer response
        let rx_future = timeout(Duration::from_millis(60 * 1000), rx.recv());
        let rx = rx_future
            .await
            .wrap_err_with(|| "ACS server failed to get a response from CPE")?;
        let response = match rx {
            Some(response) => response,
            None => {
                return Err(eyre!("ACS server failed to get a response from CPE"));
            }
        };

        Ok(response)
    }

    fn soap_response_to_api(soap: &soap::Envelope) -> api::Response {
        if let Some(fault) = soap.body.fault.first() {
            api::Response::error(
                400,
                &format!(
                    "{} - {}",
                    fault.detail.cwmpfault.faultcode.text, fault.detail.cwmpfault.faultstring.text
                ),
            )
        } else if let Some(response) = soap.body.gpn_response.first() {
            let mut list = Vec::<api::GetParameterNamesResponse>::new();
            for pn in &response.parameter_list.parameter_info {
                list.push(api::GetParameterNamesResponse {
                    name: pn.name.clone(),
                    writable: pn.writable != 0,
                });
            }
            api::Response::GetParameterNames(list)
        } else if let Some(response) = soap.body.gpv_response.first() {
            let mut list = Vec::<api::GetParameterValuesResponse>::new();
            for pv in &response.parameter_list.parameter_values {
                list.push(api::GetParameterValuesResponse {
                    name: pv.name.clone(),
                    r#type: pv.value.xsi_type.clone(),
                    value: pv.value.text.clone(),
                });
            }
            api::Response::GetParameterValues(list)
        } else if let Some(response) = soap.body.spv_response.first() {
            api::Response::SetParameterValues(response.status == 0)
        } else {
            api::Response::error(400, "Unknown response from CPE")
        }
    }

    async fn transfer_to_cpe(
        &mut self,
        serial_number: &str,
        request: soap::Envelope,
    ) -> api::Response {
        match &self.cpe_transfer(serial_number, request).await {
            Ok(envelope) => Self::soap_response_to_api(envelope),
            Err(e) => {
                api::Response::error(502, &format!("Failed to transfer request to CPE: {:?}", e))
            }
        }
    }

    async fn soap_response(soap_result: &Result<soap::Envelope>) -> Result<Response<Full<Bytes>>> {
        match soap_result {
            Ok(envelope) => {
                let s = format!("> {:?}:\n{}\n", envelope.kind(), envelope);
                utils::reply(200, s)
            }
            Err(err) => {
                let s = format!("> Error:\n{:?}\n", err);
                utils::reply(400, s)
            }
        }
    }

    async fn handle_gpn_request(
        &mut self,
        serial_number: &str,
        content: &str,
    ) -> Result<Response<Full<Bytes>>> {
        let mut envelope = soap::Envelope::new("");
        envelope.add_gpn(content, true);
        let result = self.cpe_transfer(serial_number, envelope).await;
        Self::soap_response(&result).await
    }

    async fn handle_gpv_request(
        &mut self,
        serial_number: &str,
        content: &str,
    ) -> Result<Response<Full<Bytes>>> {
        let mut envelope = soap::Envelope::new("");
        let gpv = envelope.add_gpv();
        for param in content.split(';') {
            gpv.push(param);
        }
        let result = self.cpe_transfer(serial_number, envelope).await;
        Self::soap_response(&result).await
    }

    async fn handle_spv_request(
        &mut self,
        serial_number: &str,
        content: &str,
    ) -> Result<Response<Full<Bytes>>> {
        let mut gpv_envelope = soap::Envelope::new("");
        let mut spv_envelope = soap::Envelope::new("");
        let gpv = gpv_envelope.add_gpv();
        let spv = spv_envelope.add_spv(1);
        let regex_key_type_value = Regex::new(r"(.+)<(.+)>=(.+)")?;
        let regex_key_value = Regex::new(r"(.+)=(.+)")?;
        for param in content.split(';') {
            match regex_key_type_value.captures(param) {
                Some(captures) => {
                    let key = captures.get(1).ok_or(eyre!("invalid expression"))?.as_str();
                    let base_type = captures.get(2).ok_or(eyre!("invalid expression"))?.as_str();
                    let xsd_type = format!("xsd:{}", base_type);
                    let value = captures.get(3).ok_or(eyre!("invalid expression"))?.as_str();
                    //println!("SPV({},{},{})", key, xsd_type, value);
                    spv.push(soap::ParameterValue::new(key, &xsd_type, value));
                }
                None => {
                    // let's query the parameter type with a GPV
                    let captures = regex_key_value
                        .captures(param)
                        .ok_or(eyre!("invalid expression"))?;

                    let key = captures.get(1).ok_or(eyre!("invalid expression"))?.as_str();
                    let value = captures.get(2).ok_or(eyre!("invalid expression"))?.as_str();
                    gpv.push(key);
                    spv.push(soap::ParameterValue::new(key, "", value));
                }
            };
        }

        // Send a GPV to deduct the parameter types
        if gpv.len() > 0 {
            let result = self.cpe_transfer(serial_number, gpv_envelope).await?;
            let response = match result.body.gpv_response.first() {
                Some(response) => response,
                None => {
                    return Self::soap_response(&Ok(result)).await;
                }
            };
            for gpv_pv in &response.parameter_list.parameter_values {
                for spv_pv in &mut spv.parameter_list.parameter_values {
                    if gpv_pv.name != spv_pv.name {
                        continue;
                    }
                    spv_pv.value.xsi_type = gpv_pv.value.xsi_type.clone();
                }
            }
        }

        let result = self.cpe_transfer(serial_number, spv_envelope).await;
        Self::soap_response(&result).await
    }

    async fn handle_download_request(
        &mut self,
        serial_number: &str,
        content: &str,
    ) -> Result<Response<Full<Bytes>>> {
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
        let download: Download = serde_qs::from_str(content)?;

        let mut envelope = soap::Envelope::new("");
        envelope
            .add_download()
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

        let result = self.cpe_transfer(serial_number, envelope).await;
        Self::soap_response(&result).await
    }

    async fn handle_upgrade_request(
        &mut self,
        serial_number: &str,
        content: &str,
    ) -> Result<Response<Full<Bytes>>> {
        #[derive(Debug, PartialEq, Default, Deserialize, Serialize)]
        struct Upgrade {
            #[serde(default)]
            file_name: String,
        }
        let upgrade: Upgrade = serde_qs::from_str(content)?;

        let acs = self.acs.read().await;
        let url = format!("${{baseurl}}/download/{}", upgrade.file_name);
        let mut envelope = soap::Envelope::new("");
        envelope
            .add_download()
            .set_command_key("upgrade")
            .set_file_type("1 Firmware Upgrade Image")
            .set_url(&url)
            .set_username(&acs.config.username)
            .set_password(&acs.config.password)
            .set_target_file_name(&upgrade.file_name);
        drop(acs);

        let result = self.cpe_transfer(serial_number, envelope).await;
        Self::soap_response(&result).await
    }

    async fn handle_list_request(&self) -> Result<Response<Full<Bytes>>> {
        let acs = self.acs.read().await;
        let mut s = format!("{}x Managed CPEs:\n", acs.cpe_list.len());

        for (sn, cpe) in &acs.cpe_list {
            let cpe = cpe.read().await;
            s += &format!(
                "{} - {} - {} - {} \n",
                sn, cpe.connreq.url, cpe.connreq.username, cpe.connreq.password
            );
        }
        utils::reply(200, s)
    }

    async fn handle_snlist_request(&self) -> Result<Response<Full<Bytes>>> {
        let acs = self.acs.read().await;
        let mut s = String::new();

        for sn in acs.cpe_list.keys() {
            s += &format!("{}\n", sn);
        }
        utils::reply(200, s)
    }

    async fn handle_stats_request(&self) -> Result<Response<Full<Bytes>>> {
        let s = "Stats not implemented".to_string();
        utils::reply(200, s)
    }

    async fn get_parameter_names(
        &mut self,
        serial_number: &str,
        gpn: &api::GetParameterNames,
    ) -> api::Response {
        let mut envelope = soap::Envelope::new("");
        envelope.add_gpn(&gpn.name, gpn.next_level);
        self.transfer_to_cpe(serial_number, envelope).await
    }

    async fn get_parameter_values(
        &mut self,
        serial_number: &str,
        gpv: &Vec<api::GetParameterValues>,
    ) -> api::Response {
        let mut envelope = soap::Envelope::new("");
        let soap_gpv = envelope.add_gpv();
        for param in gpv {
            soap_gpv.push(&param.name);
        }
        self.transfer_to_cpe(serial_number, envelope).await
    }

    async fn set_parameter_values(
        &mut self,
        serial_number: &str,
        spv: &Vec<api::SetParameterValues>,
    ) -> api::Response {
        let mut gpv_envelope = soap::Envelope::new("");
        let mut spv_envelope = soap::Envelope::new("");
        let soap_gpv = gpv_envelope.add_gpv();
        let soap_spv = spv_envelope.add_spv(1);
        for param in spv {
            if param.r#type.is_empty() {
                // let's query the parameter type with a GPV
                soap_gpv.push(&param.name);
                soap_spv.push(soap::ParameterValue::new(&param.name, "", &param.value));
            } else {
                soap_spv.push(soap::ParameterValue::new(
                    &param.name,
                    &param.r#type,
                    &param.value,
                ));
            }
        }

        // Send a GPV to deduct the parameter types
        if soap_gpv.len() > 0 {
            let result = match self.cpe_transfer(serial_number, gpv_envelope).await {
                Ok(result) => result,
                Err(e) => {
                    return api::Response::error(
                        502,
                        &format!("Failed to transfer GPV request to CPE: {:?}", e),
                    );
                }
            };
            let response = match result.body.gpv_response.first() {
                Some(response) => response,
                None => {
                    return Self::soap_response_to_api(&result);
                }
            };
            for gpv_pv in &response.parameter_list.parameter_values {
                for spv_pv in &mut soap_spv.parameter_list.parameter_values {
                    if gpv_pv.name != spv_pv.name {
                        continue;
                    }
                    spv_pv.value.xsi_type = gpv_pv.value.xsi_type.clone();
                }
            }
        }

        self.transfer_to_cpe(serial_number, spv_envelope).await
    }

    async fn upgrade(&mut self, serial_number: &str, upgrade: &api::Upgrade) -> api::Response {
        let acs = self.acs.read().await;
        let url = format!("${{baseurl}}/download/{}", upgrade.file_name);
        let mut envelope = soap::Envelope::new("");
        envelope
            .add_download()
            .set_command_key("upgrade")
            .set_file_type("1 Firmware Upgrade Image")
            .set_url(&url)
            .set_username(&acs.config.username)
            .set_password(&acs.config.password)
            .set_target_file_name(&upgrade.file_name);
        drop(acs);

        self.transfer_to_cpe(serial_number, envelope).await
    }

    async fn list(&self) -> api::Response {
        let mut cpe_list = Vec::<api::CPE>::new();
        let acs = self.acs.read().await;

        for (sn, cpe) in &acs.cpe_list {
            let cpe = cpe.read().await;
            cpe_list.push(api::CPE {
                sn: sn.clone(),
                url: cpe.connreq.url.clone(),
                username: cpe.connreq.username.clone(),
                password: cpe.connreq.password.clone(),
            });
        }
        api::Response::List(cpe_list)
    }

    async fn api(&mut self, content: &str) -> api::Response {
        let request: api::Request = match serde_json::from_str(content) {
            Ok(request) => request,
            Err(e) => {
                return api::Response::error(
                    400,
                    &format!("Failed to parse JSON content from /api request: {:?}", e),
                );
            }
        };

        match &request.command {
            api::Command::GetParameterNames(gpn) => {
                self.get_parameter_names(&request.serial_number, gpn).await
            }
            api::Command::GetParameterValues(gpv) => {
                self.get_parameter_values(&request.serial_number, gpv).await
            }
            api::Command::SetParameterValues(spv) => {
                self.set_parameter_values(&request.serial_number, spv).await
            }
            api::Command::Upgrade(upgrade) => self.upgrade(&request.serial_number, upgrade).await,
            api::Command::List => self.list().await,
        }
    }

    async fn handle_api_request(&mut self, content: &str) -> Result<Response<Full<Bytes>>> {
        let response = self.api(content).await;
        let status = match &response {
            api::Response::Error(e) => e.status,
            _ => 200,
        };
        let s = serde_json::to_string(&response)?;
        utils::reply(status, s)
    }

    async fn handle_welcome_request(&self) -> Result<Response<Full<Bytes>>> {
        let mut s = "Welcome on ACS Server\n".to_string();
        s += "Server is manageable on /api url with JSON APIs\n";
        s += "JSON APIs are defined in https://github.com/guillaumepellegrino/acsrs/blob/master/src/api.rs\n";
        utils::reply(200, s)
    }

    async fn handle_err404(
        &self,
        req: &mut Request<IncomingBody>,
        content: &str,
    ) -> Result<Response<Full<Bytes>>> {
        let s = format!("Unknown request: {}\n", req.uri());
        println!("{}", content);
        utils::reply(404, s)
    }

    // TODO:
    // - Check if a session is already opened before sending a ConnectionRequest.
    // - Maintain the connection to CPE open as long as one management session is opened.
    //
    pub async fn handle(
        &mut self,
        req: &mut Request<IncomingBody>,
    ) -> Result<Response<Full<Bytes>>> {
        let command = utils::req_path(req, 1);
        let serial_number = utils::req_path(req, 2);
        let content = utils::content(req).await?;
        let reply = match command.as_str() {
            "gpn" => self.handle_gpn_request(&serial_number, &content).await,
            "gpv" => self.handle_gpv_request(&serial_number, &content).await,
            "spv" => self.handle_spv_request(&serial_number, &content).await,
            "download" => self.handle_download_request(&serial_number, &content).await,
            "upgrade" => self.handle_upgrade_request(&serial_number, &content).await,
            "list" => self.handle_list_request().await,
            "snlist" => self.handle_snlist_request().await,
            "stats" => self.handle_stats_request().await,
            "api" => self.handle_api_request(&content).await,
            "" => self.handle_welcome_request().await,
            _ => self.handle_err404(req, &content).await,
        };

        match reply {
            Ok(reply) => Ok(reply),
            Err(error) => utils::reply_error(error),
        }
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
