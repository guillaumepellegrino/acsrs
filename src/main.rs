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
mod acs;
mod mng;
mod session;
mod soap;
mod utils;
mod db;

use std::io::Read;
use std::sync::{Arc};
use std::net::SocketAddr;
use tokio;
use tokio::sync::{RwLock};
use tokio::net::TcpListener;
//use tokio::io::{AsyncReadExt, AsyncWriteExt};
use native_tls::Identity;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request};
use crate::acs::{*};
use crate::session::{*};


fn home() -> std::path::PathBuf {
    let home = std::env::var("HOME").expect("Failed to get HOME directory");
    std::path::Path::new(&home).to_path_buf()
}

#[tokio::main]
async fn main() {
    let acsdir = home().join(".acsrs");
    let savefile = acsdir.join("config.toml");
    let identityfile = acsdir.join("identity.p12");

    // Create config directory if doesn't exist
    if !acsdir.is_dir() {
        println!("Create config directory: {:?}", acsdir);
        if let Err(err) = std::fs::create_dir(&acsdir) {
            println!("Failed to create {:?} directory: {:?}", acsdir, err);
            return;
        }
    }

    // Restore ACS from config file or create a new one
    let acs = match Acs::restore(&savefile).await {
        Ok(acs) => {
            println!("ACS config restored from {:?}", savefile);
            acs
        },
        Err(err) => {
            println!("Could not restore ACS config from {:?}: {:?}", savefile, err);
            let acs = Acs::new(&savefile);
            if let Err(err) = acs.save().await {
                println!("Failed to save ACS config to {:?}: {:?}", savefile, err);
            }
            acs
        },
    };

    // Create TCP listener waiting for unsecure connection from CPEs
    let cpe_addr: SocketAddr = acs.config.unsecure_address.parse().unwrap();
    let cpe_listener = TcpListener::bind(cpe_addr).await.unwrap();
    println!("ACS listening on unsecure port {:?}", cpe_addr);

    // Create TCP/TLS listener waiting for secure connection from CPEs
    // Open or create identity file for TLS Server
    if !identityfile.exists() {
        println!("Generate certificates in {:?}", acsdir);
        utils::gencertificates(&acsdir);
        if !identityfile.exists() {
            println!("Failed to create {:?}", identityfile);
            return;
        }
    }
    let mut der = Vec::new();
    let file = std::fs::File::open(identityfile).unwrap();
    let mut reader = std::io::BufReader::new(file);
    reader.read_to_end(&mut der).unwrap();
    let cert = Identity::from_pkcs12(&der, &acs.config.identity_password).unwrap();
    let tls_acceptor = tokio_native_tls::TlsAcceptor::from(native_tls::TlsAcceptor::builder(cert).build().unwrap());
    let sec_addr: SocketAddr = acs.config.secure_address.parse().unwrap();
    let sec_listener = TcpListener::bind(sec_addr).await.unwrap();
    println!("ACS listening on secure port   {:?}", sec_addr);

    // Create TCP listener for management
    let mng_addr: SocketAddr = acs.config.management_address.parse().unwrap();
    let mng_listener = TcpListener::bind(mng_addr).await.unwrap();
    println!("Management server listening on {:?}", mng_addr);

    // We are entering multi-threaded code: Lock the ACS context
    let acs = Arc::new(RwLock::new(acs));
    let cpe_acs = acs.clone();
    let sec_acs = acs.clone();
    let mng_acs = acs.clone();

    // Print ACS configuration
    // The public IP Address is retrieved
    // from a server with an async HTTP request
    tokio::task::spawn(async move {
        acs.read().await.print_config().await;
    });

    // Unsecure server event loop
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

    // Secure server event loop
    let sec_srv = async move {
        loop {
            let (stream, _) = sec_listener.accept().await.unwrap();
            let acs = sec_acs.clone();
            let tls_acceptor = tls_acceptor.clone();
            tokio::task::spawn(async move {
                println!("TCPc acceptor in");
                let tls_stream = tls_acceptor.accept(stream)
                    .await.expect("accept error");

                println!("TCPc acceptor out");

                let session = Arc::new(RwLock::new(Session::new(acs)));
                let service = |mut req: Request<hyper::body::Incoming>| {
                    let session = session.clone();
                    return async move {
                        let mut session = session.write().await;
                        return session.handle(&mut req).await;
                    };
                };
                if let Err(err) = http1::Builder::new()
                    .serve_connection(tls_stream, service_fn(service))
                    .await
                {
                    println!("Failed to serve connection: {:?}", err);
                }
            });
        }
    };

    // Management server event loop
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

    // Join the three event loop in one unique future
    futures::future::join3(cpe_srv, sec_srv, mng_srv).await;
}
