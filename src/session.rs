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
use crate::soap;
use crate::utils;
use bytes::Bytes;
use eyre::Result;
use http_body_util::Full;
use hyper::{body::Incoming as IncomingBody, Request, Response};
use std::net::SocketAddr;
use std::sync::Arc;

use log::*;
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use tokio::sync::{mpsc, RwLock};
use tokio::time::{timeout, Duration};

pub struct TR069Session {
    acs: Arc<RwLock<Acs>>,
    cpe: Option<Arc<RwLock<CPE>>>,
    observer: Option<mpsc::Sender<soap::Envelope>>,
    refcount: Option<Arc<()>>,
    srvaddr: SocketAddr,
    secure: bool,
    sn: String,
    id: String,
    counter: u32,
}

impl TR069Session {
    pub fn new(acs: Arc<RwLock<Acs>>, srvaddr: SocketAddr, secure: bool) -> Self {
        Self {
            acs,
            cpe: None,
            observer: None,
            refcount: None,
            srvaddr,
            secure,
            sn: String::new(),
            id: String::from("0"),
            counter: 0,
        }
    }

    async fn cpe_notify_observers(&mut self, inform: &soap::Inform) {
        let acs = self.acs.read().await;
        if acs.observers.receiver_count() == 0 {
            return;
        }
        if let Err(e) = acs.observers.send(inform.clone()) {
            error!("Failed to notify observers: {:?}", e);
        }
    }

    async fn cpe_handle_inform(&mut self, inform: &soap::Inform) {
        let mut igd = false;
        let connreq_url = match inform
            .parameter_list
            .get_value("Device.ManagementServer.ConnectionRequestURL")
        {
            Some(value) => value,
            None => {
                match inform
                    .parameter_list
                    .get_value("InternetGatewayDevice.ManagementServer.ConnectionRequestURL")
                {
                    Some(value) => {
                        igd = true;
                        value
                    }
                    None => {
                        warn!("[SN:{}][SID:{}][{}] Inform message does not contain ConnectionRequestURL", self.sn, self.id, self.counter);
                        return;
                    }
                }
            }
        };

        let (connreq_username_path, connreq_password_path) = match igd {
            true => (
                "InternetGatewayDevice.ManagementServer.ConnectionRequestUsername",
                "InternetGatewayDevice.ManagementServer.ConnectionRequestPassword",
            ),
            false => (
                "Device.ManagementServer.ConnectionRequestUsername",
                "Device.ManagementServer.ConnectionRequestPassword",
            ),
        };

        let mut acs = self.acs.write().await;
        let cpelock = acs
            .cpe_list
            .entry(inform.device_id.serial_number.clone())
            .or_default()
            .clone();
        drop(acs);
        self.cpe = Some(cpelock.clone());
        let mut cpe = cpelock.write().await;
        if self.refcount.is_none() {
            self.refcount = Some(cpe.get_tr069_session_refcount());
        }
        cpe.device_id = inform.device_id.clone();
        if cpe.connreq.url != connreq_url || inform.event.contains("0 BOOTSTRAP") {
            info!("connreq.url is not configred: Configure ConnectionRequest");

            info!(
                "[SN:{}][SID:{}][{}] Unknown ConnReqURL: Configure CPE ConnectionRequest",
                self.sn, self.id, self.counter
            );
            cpe.connreq.url = String::from(connreq_url);

            // Push a tranfer to configure ConnectionRequest with an SPV
            let mut transfer = Transfer::new();
            let spv = transfer.msg.add_spv(1);
            spv.push(soap::ParameterValue::new(
                connreq_username_path,
                "xsd:string",
                &cpe.connreq.username,
            ));
            spv.push(soap::ParameterValue::new(
                connreq_password_path,
                "xsd:string",
                &cpe.connreq.password,
            ));

            drop(cpe);
            let controller = CPEController::new(cpelock.clone()).await;
            if let Err(err) = controller.add_transfer(transfer).await {
                error!(
                    "[SN:{}][SID:{}][{}] Failed to configure CPE ConnectionRequest: {:?}",
                    self.sn, self.id, self.counter, err
                );
            }

            // Save configuration in a dedicated task
            let acs = self.acs.clone();
            tokio::task::spawn(async move {
                if let Err(err) = acs.read().await.save().await {
                    error!("Failed to save ACS config: {:?}", err);
                }
            });
        }
    }

    fn soap_download_set_baseurl(
        &self,
        download: &mut soap::Download,
        req: &mut Request<IncomingBody>,
    ) {
        if let Some(host) = req.headers().get("host") {
            let host = host.to_str().unwrap_or("");
            let protocol = match self.secure {
                true => "https",
                false => "http",
            };
            let baseurl = format!("{}://{}:{}", protocol, host, self.srvaddr.port());
            download.url.text = download.url.text.replace("${baseurl}", &baseurl);
            info!("downloadurl={}", download.url.text);
        }
    }

    async fn cpe_check_transfers(
        &mut self,
        req: &mut Request<IncomingBody>,
    ) -> Result<Response<Full<Bytes>>> {
        let mut transfer;
        let cpelock = match &self.cpe {
            Some(cpelock) => cpelock,
            None => {
                info!(
                    "[SN:??][SID:??][{}] Send: Reply with no content (Unknown CPE)",
                    self.counter
                );
                return utils::reply(204, String::from(""));
            }
        };
        let rx = cpelock.read().await.get_transfers_rx();
        loop {
            let rx_future = timeout(Duration::from_millis(3 * 1000), rx.recv_async());
            match rx_future.await {
                Ok(rx) => {
                    transfer = match rx {
                        Ok(transfer) => transfer,
                        Err(err) => {
                            info!("[SN:{}][SID:{}][{}] Send: Reply with no content (Error reading transfer queue: {:?})",
                            self.sn, self.id, self.counter, err);
                            return utils::reply(204, String::from(""));
                        }
                    };
                    break;
                }
                Err(_) => {
                    if !cpelock.read().await.cpe_controller_running() {
                        info!("[SN:{}][SID:{}][{}] Send: Reply with no content (no pending transfer for CPE)",
                            self.sn, self.id, self.counter);
                        return utils::reply(204, String::from(""));
                    }
                }
            };
        }
        transfer.msg.header.id.text = self.id.clone();
        if let Some(download) = transfer.msg.body.download.first_mut() {
            self.soap_download_set_baseurl(download, req);
        }

        self.observer = transfer.observer;

        info!(
            "[SN:{}][SID:{}][{}] Send: Transfer pending {:?} to CPE",
            self.sn,
            self.id,
            self.counter,
            transfer.msg.kind()
        );
        utils::reply_xml(&transfer.msg)
    }

    async fn handle_cpe_request(
        &mut self,
        req: &mut Request<IncomingBody>,
    ) -> Result<Response<Full<Bytes>>> {
        //info!("Received from CPE");
        //info!("  Headers: {:?}", req.headers());

        let content = utils::content(req).await?;
        //info!("  Content: [\n{}\n]", content);

        //  The CPE has nothing to tell us: We may ask for a new Transfer
        if content.is_empty() {
            info!("[SN:{}][SID:{}][{}] Received: Empty content => Check pending transfers for this CPE",
                self.sn, self.id, self.counter);
            return self.cpe_check_transfers(req).await;
        }

        // Try to parse XML content
        let envelope: soap::Envelope = match quick_xml::de::from_str(&content) {
            Ok(value) => value,
            Err(e) => {
                error!("Failed to parse XML: {:?}", e);
                error!("Content: [\n{}\n]\nContent End", content);
                return utils::reply(204, String::from(""));
            }
        };

        // Process message sent by CPE
        if let Some(inform) = envelope.inform() {
            self.id = envelope.id().to_string();
            self.sn = inform.device_id.serial_number.clone();
            info!(
                "[SN:{}][SID:{}][{}] Received: Inform message",
                self.sn, self.id, self.counter
            );

            for event in &inform.event.event_struct {
                info!(
                    "[SN:{}][SID:{}][{}]      Event: {}",
                    self.sn, self.id, self.counter, event.event_code
                );
            }
            self.cpe_handle_inform(inform).await;
            self.cpe_notify_observers(inform).await;

            info!(
                "[SN:{}][SID:{}][{}] Send: Inform Response",
                self.sn, self.id, self.counter
            );
            let mut response = soap::Envelope::new(envelope.id());
            response.add_inform_response();
            return utils::reply_xml(&response);
        } else if let Some(_gpn_response) = envelope.body.gpn_response.first() {
            info!(
                "[SN:{}][SID:{}][{}] Received: GPN Response",
                self.sn, self.id, self.counter
            );
        } else if let Some(_gpv_response) = envelope.body.gpv_response.first() {
            info!(
                "[SN:{}][SID:{}][{}] Received: GPV Response",
                self.sn, self.id, self.counter
            );
        } else if let Some(spv_response) = envelope.body.spv_response.first() {
            info!(
                "[SN:{}][SID:{}][{}] Received: SPV Response = {}",
                self.sn, self.id, self.counter, spv_response.status
            );
        } else if let Some(aobj_response) = envelope.body.aobj_response.first() {
            info!(
                "[SN:{}][SID:{}][{}] Received: AddObject Response => {}: {}",
                self.sn,
                self.id,
                self.counter,
                aobj_response.instance_number,
                if aobj_response.status == 1 {
                    "Pending"
                } else {
                    "Added"
                }
            );
        } else if let Some(dobj_response) = envelope.body.dobj_response.first() {
            info!(
                "[SN:{}][SID:{}][{}] Received: DeleteObject Response => {}",
                self.sn,
                self.id,
                self.counter,
                if dobj_response.status == 1 {
                    "Pending"
                } else {
                    "Deleted"
                }
            );
        } else if let Some(download_response) = envelope.body.download_response.first() {
            info!(
                "[SN:{}][SID:{}][{}] Received: Download Response = {}",
                self.sn, self.id, self.counter, download_response.status
            );
        } else if let Some(transfer_complete) = envelope.body.transfer_complete.first() {
            info!(
                "[SN:{}][SID:{}][{}] Received: TransferComplete = {:?}",
                self.sn, self.id, self.counter, transfer_complete
            );

            let mut response = soap::Envelope::new(envelope.id());
            response.add_transfer_complete_response();
            return utils::reply_xml(&response);
        } else if let Some(fault) = envelope.body.fault.first() {
            info!(
                "[SN:{}][SID:{}][{}] Received: Fault: {} - {}",
                self.sn,
                self.id,
                self.counter,
                fault.detail.cwmpfault.faultcode.text,
                fault.detail.cwmpfault.faultstring.text
            );
        } else {
            error!(
                "[SN:{}][SID:{}][{}] Received: Unexpected SOAP/XML Request: {}",
                self.sn, self.id, self.counter, content
            );
            return utils::reply(204, String::from(""));
        }

        // If someone if observing the current Transfer,
        // we forward the CPE response to him.
        if let Some(observer) = self.observer.as_mut() {
            if let Err(err) = observer.send(envelope).await {
                error!(
                    "[SN:{}][SID:{}][{}] Failed to forward response to observer: {:?}",
                    self.sn, self.id, self.counter, err
                );
            }
            self.observer = None;
        }

        // We may ask for a new Transfer
        self.cpe_check_transfers(req).await
    }

    async fn handle_download(
        &mut self,
        req: &mut Request<IncomingBody>,
    ) -> Result<Response<Full<Bytes>>> {
        let download = utils::req_path(req, 1);
        let path = utils::req_path(req, 2);
        info!("Handle Download of {}", path);
        let acs = self.acs.read().await;
        let acsdir = acs.acsdir.clone();
        drop(acs);

        let mut contents = vec![];
        let filepath = acsdir.join(download).join(path);
        let mut file = File::open(&filepath).await?;
        file.read_to_end(&mut contents).await?;
        let response = Response::new(Full::new(Bytes::from(contents)));
        Ok(response)
    }

    async fn authorization_error(
        &mut self,
        req: &mut Request<IncomingBody>,
    ) -> Option<Result<Response<Full<Bytes>>>> {
        match req.headers().get("authorization") {
            Some(wwwauth) => {
                let wwwauth = match wwwauth.to_str() {
                    Ok(value) => value,
                    Err(e) => {
                        return Some(Err(e.into()));
                    }
                };
                if wwwauth == self.acs.read().await.basicauth {
                    None
                } else {
                    warn!(
                        "[SN:??][SID:??][{}] Access forbidden: {}",
                        self.counter, wwwauth
                    );
                    Some(utils::reply(403, String::from("Forbidden\n")))
                }
            }
            None => {
                info!("[SN:??][SID:??][{}] Authorization required", self.counter);
                let response = String::from("Authorization required\n");
                let builder = Response::builder()
                    .header("User-Agent", "acsrs")
                    .header("WWW-Authenticate", "Basic realm=\"acrsrs world\"")
                    .status(401);

                match builder.body(Full::new(Bytes::from(response))) {
                    Ok(body) => Some(Ok(body)),
                    Err(e) => Some(Err(e.into())),
                }
            }
        }
    }

    pub async fn handle(
        &mut self,
        req: &mut Request<IncomingBody>,
    ) -> Result<Response<Full<Bytes>>> {
        self.counter += 1;

        if let Some(reply) = self.authorization_error(req).await {
            return reply;
        }

        let command = utils::req_path(req, 1);
        let reply = match command.as_str() {
            "cwmpWeb" => self.handle_cpe_request(req).await,
            "download" => self.handle_download(req).await,
            _ => utils::reply(403, String::from("Forbidden\n")),
        };

        match reply {
            Ok(reply) => Ok(reply),
            Err(error) => utils::reply_error(error),
        }
    }
}
