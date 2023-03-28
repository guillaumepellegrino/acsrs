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
use bytes::Bytes;
use http_body_util::{Full, BodyExt};
use hyper::{body::Incoming as IncomingBody, Request, Response};
use crate::soap;
use rand::{thread_rng, Rng, distributions::Alphanumeric};
use std::io::Write;

pub fn req_path(req: &Request<IncomingBody>, num: u32) -> String {
    let mut i = 0;
    let mut split = req.uri().path().split('/');

    while i < num {
        split.next();
        i += 1;
    }

    match split.next() {
        Some(path) => String::from(path),
        None => String::from(""),
    }
}

pub fn reply(statuscode: u16, response: String) -> Result<Response<Full<Bytes>>, Box<dyn std::error::Error>> {
    let builder = Response::builder()
        .status(statuscode);
    let reply = builder.body(Full::new(Bytes::from(response)))?;
    Ok(reply)
}

pub fn reply_xml(response: &soap::Envelope) -> Result<Response<Full<Bytes>>, Box<dyn std::error::Error>> {
    let text = quick_xml::se::to_string(&response)?;
    let builder = Response::builder()
        .header("User-Agent", "acsrs")
        .header("Content-type", "text/xml; charset=\"utf-8\"");
    let reply = builder.body(Full::new(Bytes::from(text)))?;
    Ok(reply)
}

pub fn reply_error(err: Box<dyn std::error::Error>) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let reply = format!("Server internal error: {:?}\n", err);
    println!("{}", reply);
    Ok(Response::builder()
        .status(500)
        .body(Full::new(Bytes::from(reply))).unwrap())
}

pub async fn content(req: &mut Request<IncomingBody>) -> Result<String, Box<dyn std::error::Error>> {
    let body = req.collect().await?.to_bytes();
    Ok(String::from_utf8(body.to_vec())?)
}

pub fn random_password() -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(30)
        .map(char::from)
        .collect()
}

// Generate default certificates for a secure ACS connection with the specified CommonName
// Pipe acsrs/ssl/ssl.sh script into shell interpreter (cat acsrs/ssl/ssl.sh | bash)
pub fn gencertificates(acsdir: &std::path::Path, common_name: &str) {
    let bytes = include_bytes!("../ssl/ssl.sh");

    let mut child = std::process::Command::new("bash")
        .current_dir(acsdir)
        .env("CN", common_name)
        .stdin(std::process::Stdio::piped())
        .spawn().unwrap();

    let child_stdin = child.stdin.as_mut().unwrap();
    child_stdin.write_all(bytes).unwrap();
    drop(child_stdin);

    let status = child.wait().unwrap().success();

    println!("status: {}", status);
}
