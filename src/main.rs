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
mod soap;
mod utils;
mod acs;
mod mng;

use std::sync::{Arc};
use std::net::SocketAddr;
use std::collections::VecDeque;
use std::collections::HashMap;
use bytes::Bytes;
use http_body_util::{Full};
use tokio;
use tokio::sync::{RwLock};
use tokio::time::{Duration, timeout};
use tokio::net::TcpListener;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{body::Incoming as IncomingBody, Request, Response};
use regex::Regex;
use crate::acs::{*};

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
                        return mng::handle_request(acs, &mut req).await;
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
