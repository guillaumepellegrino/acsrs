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
mod cli;

use std::io::Read;
use std::sync::{Arc};
use std::net::SocketAddr;
use tokio;
use tokio::sync::{RwLock};
use tokio::net::TcpListener;
use native_tls::Identity;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request};
use crate::acs::{*};
use crate::session::{*};
use crate::mng::ManagementSession;
use clap::{arg, command};
use eyre::{Result, eyre, WrapErr};

/// Return the PUBLIC IP Address of this machine
/// by querying http://ifconfig.me.
async fn get_public_ipaddress() -> Result<String> {
    let server = "http://ifconfig.me";
    let response = reqwest::get(server).await?;
    let ipaddress = response.text().await?;
    Ok(ipaddress)
}

/// Return the path to $HOME directory
fn home() -> std::path::PathBuf {
    let home = std::env::var("HOME").expect("Failed to get HOME directory");
    std::path::Path::new(&home).to_path_buf()
}

#[tokio::main]
async fn main() -> Result<()> {
    let matches = command!()
        .about("Auto Configuration Server")
        .arg(arg!(-c --config<PATH> "Specify config directory (default: ~/.acsrs/ )"))
        .arg(arg!(--cli "Run ACS cli"))
        .arg(arg!(-d --daemon "Run as a daemon"))
        .get_matches();

    if matches.get_flag("cli") {
        return cli::main().await;
    }

    let acsdir = match matches.get_one::<std::path::PathBuf>("config") {
        Some(value) => value.clone(),
        None =>  home().join(".acsrs"),
    };
    let identityfile = acsdir.join("identity.p12");
    let pidfile = acsdir.join("acsrs.pid");
    let downloaddir = acsdir.join("download");

    // Create config directory if doesn't exist
    if !acsdir.is_dir() {
        println!("Create config directory: {:?}", acsdir);
        std::fs::create_dir(&acsdir)
            .wrap_err_with(|| {format!("Failed to create acs config directory at {:?}", acsdir)})?;
    }
    if !downloaddir.is_dir() {
        std::fs::create_dir(&downloaddir)
            .wrap_err_with(|| {format!("Failed to create download directory at {:?}", downloaddir)})?;
    }

    // Restore ACS from config file or create a new one
    let acs = match Acs::restore(&acsdir).await {
        Ok(acs) => {
            println!("ACS config restored from {:?}", acsdir);
            acs
        },
        Err(err) => {
            println!("Could not restore ACS config from {:?}: {:?}", acsdir, err);
            let acs = Acs::new(&acsdir);
            if let Err(err) = acs.save().await {
                println!("Failed to save ACS config to {:?}: {:?}", acsdir, err);
            }
            acs
        },
    };

    // Get server hostname
    let mut hostname = acs.config.hostname.clone();
    if hostname == "" {
        // hostname was not provided in configuration
        // Try to guess our public IP Address
        hostname = get_public_ipaddress().await
            .wrap_err_with(|| {format!("Failed to get public IP Address")})?;
    }

    // Create automated certificates
    if acs.config.autocert {
        println!("Update certificates for CN={} in {:?}", hostname, acsdir);
        utils::gencertificates(&acsdir, &hostname);
        if !identityfile.exists() {
            return Err(eyre!("Failed to create {:?}", identityfile));
        }
    }

    // Create TCP/TLS listener waiting for secure connection from CPEs
    // Open or create identity file for TLS Server
    let mut der = Vec::new();
    let file = std::fs::File::open(&identityfile)
        .wrap_err_with(|| {format!("Failed to open {:?}", identityfile)})?;
    let mut reader = std::io::BufReader::new(file);
    reader.read_to_end(&mut der)
        .wrap_err_with(|| {format!("Failed to read {:?}", identityfile)})?;
    let cert = Identity::from_pkcs12(&der, &acs.config.identity_password)
        .wrap_err_with(|| {format!("Failed to decrypt {:?} with provided password", identityfile)})?;
    let tls_acceptor = tokio_native_tls::TlsAcceptor::from(native_tls::TlsAcceptor::builder(cert).build()
        .wrap_err_with(|| {format!("Failed to build TLS Acceptor for secure server from identity: {:?}", identityfile)})?);
    let sec_addr: SocketAddr = acs.config.secure_address.parse()
        .wrap_err_with(|| {format!("config::secure_address ({}) is not a socket address", acs.config.secure_address)})?;
    let sec_listener = TcpListener::bind(sec_addr).await
        .wrap_err_with(|| {format!("Failed to bind {}: Is the ACS server already running ?", acs.config.secure_address)})?;
    println!("ACS listening on secure port   {:?}", sec_addr);

    // Create TCP listener waiting for unsecure connection from CPEs
    let cpe_addr: SocketAddr = acs.config.unsecure_address.parse()
        .wrap_err_with(|| {format!("config::unsecure_address ({}) is not a socket address", acs.config.unsecure_address)})?;
    let cpe_listener = TcpListener::bind(cpe_addr).await
        .wrap_err_with(|| {format!("Failed to bind {}: Is the ACS server already running ?", acs.config.unsecure_address)})?;
    println!("ACS listening on unsecure port {:?}", cpe_addr);

    // Create TCP listener for management
    let mng_addr: SocketAddr = acs.config.management_address.parse()
        .wrap_err_with(|| {format!("config::management_address ({}) is not a socket address", acs.config.management_address)})?;
    let mng_listener = TcpListener::bind(mng_addr).await
        .wrap_err_with(|| {format!("Failed to bind {}: Is the ACS server already running ?", acs.config.management_address)})?;
    println!("Management server listening on {:?}", mng_addr);

    // Print ACS configuration
    acs.print_config(&hostname);

    // We are entering multi-threaded code: Lock the ACS context
    let acs = Arc::new(RwLock::new(acs));
    let cpe_acs = acs.clone();
    let sec_acs = acs.clone();
    let mng_acs = acs.clone();

    // Daemonize process if demanded
    if matches.get_flag("daemon") {
        println!("Daemonize process !");
        let daemon = daemonize::Daemonize::new()
            .pid_file(&pidfile);

        daemon.start()
            .wrap_err_with(|| {format!("Failed to daemonize")})?;
    }

    // Unsecure server event loop
    let cpe_srv = async move {
        loop {
            let (stream, _) = cpe_listener.accept().await.unwrap();
            let acs = cpe_acs.clone();
            tokio::task::spawn(async move {
                let session = Arc::new(RwLock::new(TR069Session::new(acs)));
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
                let tls_stream = match tls_acceptor.accept(stream).await {
                    Ok(value) => value,
                    Err(err) => {
                        println!("tls accept error: {:?}", err);
                        return;
                    },
                };

                let session = Arc::new(RwLock::new(TR069Session::new(acs)));
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
                let session = Arc::new(RwLock::new(ManagementSession::new(acs)));
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

    // Join the three event loop in one unique future
    futures::future::join3(cpe_srv, sec_srv, mng_srv).await;
    Ok(())
}
