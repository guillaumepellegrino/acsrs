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

mod api;
use eyre::{eyre, Result};
use regex::Regex;
use std::fmt;
use tokiocli::{Action, Cli};

struct AcsCli {
    cli: Cli,
    exit: bool,
    url: String,
    client: reqwest::Client,
    connectedto: Option<String>,
    directory: String,
}

impl fmt::Display for api::Response {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            api::Response::GetParameterNames(response) => {
                for param in response {
                    let rw = match param.writable {
                        true => "rw",
                        false => "r-",
                    };
                    writeln!(f, "{} {}", rw, param.name)?;
                }
            }
            api::Response::GetParameterValues(response) => {
                for param in response {
                    let pretty_type = match param.r#type.strip_prefix("xsd:") {
                        Some(value) => value,
                        None => &param.r#type,
                    };
                    writeln!(f, "{}<{}>={}", param.name, pretty_type, param.value)?;
                }
            }
            api::Response::SetParameterValues(response) => {
                write!(f, "SetParameterValues Status: {}", response)?;
            }
            api::Response::AddObject(response) => {
                write!(
                    f,
                    "{} => {}",
                    response.instance_number,
                    if response.status { "Pending" } else { "Added" }
                )?;
            }
            api::Response::Upgrade(response) => {
                write!(f, "Upgrade Status: {}", response.status)?;
            }
            api::Response::List(cpes) => {
                for cpe in cpes {
                    writeln!(
                        f,
                        "{} - {} - {} - {}",
                        cpe.sn, cpe.url, cpe.username, cpe.password
                    )?;
                }
            }
            api::Response::Error(response) => {
                write!(f, "Error: {:?}", response.description)?;
            }
        }
        write!(f, "")
    }
}

impl AcsCli {
    fn new() -> Result<Self> {
        Ok(Self {
            cli: Cli::new()?,
            exit: false,
            url: String::from("http://127.0.0.1:8000/api"),
            client: reqwest::Client::new(),
            connectedto: None,
            directory: String::new(),
        })
    }

    async fn sendrequest(&self, command: api::Command) -> Result<api::Response> {
        let mut request = api::Request {
            serial_number: String::new(),
            command,
        };
        if let Some(serial_number) = &self.connectedto {
            request.serial_number = serial_number.clone();
        }
        let s = serde_json::to_string(&request)?;
        let response = self.client.post(&self.url).body(s).send().await?;
        let text = response.text().await?;
        let result: api::Response = serde_json::from_str(&text)?;
        Ok(result)
    }

    fn update_prompt(&mut self) {
        let prompt = match &self.connectedto {
            Some(connectedto) => match self.directory.as_str() {
                "" => format!("{}> ", connectedto),
                _ => format!("{}:{}> ", connectedto, self.directory),
            },
            None => String::from("> "),
        };
        self.cli.setprompt(&prompt);
    }

    async fn connect(&mut self, arg1: Option<&String>) -> Result<()> {
        let serial_number = arg1;
        let serial_number = serial_number.ok_or(eyre!("Missing Serial Number argument"))?;
        println!("Connect to {}", serial_number);

        self.connectedto = Some(String::from(serial_number));
        self.update_prompt();
        Ok(())
    }

    async fn disconnect(&mut self) -> Result<()> {
        self.connectedto = None;
        self.directory = String::new();
        self.update_prompt();
        Ok(())
    }

    async fn gpv(&mut self, arg1: Option<&String>) -> Result<()> {
        let mut gpv = Vec::<api::GetParameterValues>::new();
        if let Some(arg1) = arg1 {
            for param in arg1.split(';') {
                gpv.push(api::GetParameterValues {
                    name: self.abspath(param),
                });
            }
        } else {
            gpv.push(api::GetParameterValues {
                name: self.abspath(""),
            });
        }

        let response = self
            .sendrequest(api::Command::GetParameterValues(gpv))
            .await?;
        println!("{}", response);
        Ok(())
    }

    async fn spv(&mut self, arg1: Option<&String>) -> Result<()> {
        let mut spv = Vec::<api::SetParameterValues>::new();
        let regex_key_type_value = Regex::new(r"(.+)<(.+)>=(.+)")?;
        let regex_key_value = Regex::new(r"(.+)=(.+)")?;
        let arg1 = match arg1 {
            Some(arg1) => arg1,
            None => {
                return Err(eyre!("Missing argument"));
            }
        };
        for param in arg1.split(';') {
            match regex_key_type_value.captures(param) {
                Some(captures) => {
                    let key = captures.get(1).ok_or(eyre!("invalid expression"))?.as_str();
                    let base_type = captures.get(2).ok_or(eyre!("invalid expression"))?.as_str();
                    let xsd_type = format!("xsd:{}", base_type);
                    let value = captures.get(3).ok_or(eyre!("invalid expression"))?.as_str();

                    spv.push(api::SetParameterValues {
                        name: self.abspath(key),
                        r#type: xsd_type,
                        r#value: value.to_string(),
                    });
                }
                None => {
                    let captures = regex_key_value
                        .captures(param)
                        .ok_or(eyre!("invalid expression"))?;

                    let key = captures.get(1).ok_or(eyre!("invalid expression"))?.as_str();
                    let value = captures.get(2).ok_or(eyre!("invalid expression"))?.as_str();

                    spv.push(api::SetParameterValues {
                        name: self.abspath(key),
                        r#type: String::new(),
                        r#value: value.to_string(),
                    });
                }
            }
        }

        let response = self
            .sendrequest(api::Command::SetParameterValues(spv))
            .await?;
        println!("{}", response);
        Ok(())
    }

    async fn aobj(&mut self, arg1: Option<&String>) -> Result<()> {
        let Some(aobj) = arg1.map(|s| api::AddObject {
            object_name: s.clone(),
        }) else {
            return Err(eyre!("Missing argument"));
        };

        let response = self.sendrequest(api::Command::AddObject(aobj)).await?;
        println!("{}", response);
        Ok(())
    }

    async fn upgrade(&mut self, arg1: Option<&String>) -> Result<()> {
        if self.connectedto.is_none() {
            return Err(eyre!("Not connected !"));
        }
        let file_name = arg1;
        let file_name = file_name.ok_or(eyre!("Missing file_name argument"))?;
        let upgrade = api::Upgrade {
            file_name: file_name.clone(),
        };
        let response = self.sendrequest(api::Command::Upgrade(upgrade)).await?;
        println!("{}", response);
        Ok(())
    }

    fn abspath(&self, relpath: &str) -> String {
        format!("{}{}", self.directory, relpath)
    }

    fn arg2path(&self, arg: Option<&String>) -> String {
        let relpath = match arg {
            Some(relpath) => relpath.as_str(),
            None => "",
        };
        self.abspath(relpath)
    }

    fn relpath<'a>(&self, abspath: &'a str) -> Option<&'a str> {
        abspath.strip_prefix(&self.directory)
    }

    fn objpath(path: &str) -> String {
        match path.rsplit_once('.') {
            Some((obj, _)) => format!("{}.", obj),
            None => String::new(),
        }
    }

    async fn change_directory(&mut self, arg1: Option<&String>) -> Result<()> {
        if self.connectedto.is_none() {
            return self.connect(arg1).await;
        }

        let path = match arg1 {
            Some(path) => path,
            None => {
                self.directory = String::new();
                self.update_prompt();
                return Ok(());
            }
        };

        let mut current: Vec<&str> = self.directory.split('.').collect();
        current.pop();

        match path.as_str() {
            "" | "/" => {
                current.clear();
            }
            ".." => {
                current.pop();
            }
            _ => {
                for dir in path.split('.') {
                    match dir {
                        "" => {}
                        _ => {
                            current.push(dir);
                        }
                    }
                }
            }
        }

        let mut newdir = String::new();
        for dir in current {
            if !dir.is_empty() {
                newdir += dir;
                newdir += ".";
            }
        }
        self.directory = newdir;

        self.update_prompt();
        Ok(())
    }

    async fn list_cpes(&self) -> Result<()> {
        let response = self.sendrequest(api::Command::List).await?;
        println!("{}", response);
        Ok(())
    }

    async fn list_parameters(&mut self, arg1: Option<&String>) -> Result<()> {
        let gpn = api::GetParameterNames {
            name: self.arg2path(arg1),
            next_level: true,
        };
        let response = self
            .sendrequest(api::Command::GetParameterNames(gpn))
            .await?;
        println!("{}", response);
        Ok(())
    }

    async fn list(&mut self, arg1: Option<&String>) -> Result<()> {
        match self.connectedto {
            Some(_) => self.list_parameters(arg1).await,
            None => self.list_cpes().await,
        }
    }

    fn help(&self) {
        println!("acscli: interactive cli for ACSRS");
        println!("Global commands:");
        println!(" - help: Display this help");
        println!(" - exit: Exit this application");
        println!();
        println!("Availables command when disconnected:");
        println!(" - ls: List connected CPEs to this ACS");
        println!(" - cd|connect [SN] : Connect to CPE specified by this Serial Number");
        println!();
        println!("Availables command when connected to a CPE:");
        println!(" - disconnect :  Disconnect from the current CPE");
        println!(" - ls [path]: List Parameters under current object");
        println!(" - cd [path]: Change directory");
        println!(" - get [path] | [path]? : Get object or parameter value");
        println!(" - set [path]<type>=value | [path]<type>=value : Set Parameter value");
        println!(" - add [path] | [path]+ : Add Object");
        println!(" - upgrade [filename] : Upgrade CPE to provided firmware");
    }

    async fn parse_objpath(&mut self, cmd: &str) -> Result<()> {
        if let Some((objpath, _)) = cmd.split_once('?') {
            return self.gpv(Some(&String::from(objpath))).await;
        }
        if cmd.contains('=') {
            return self.spv(Some(&String::from(cmd))).await;
        }
        if let Some((objpath, _)) = cmd.split_once('+') {
            return self.aobj(Some(&String::from(objpath))).await;
        }

        Err(eyre!("Unknown command '{}'", cmd))
    }

    async fn parse(&mut self, args: &[String]) -> Result<()> {
        let cmd = args[0].as_str();
        let arg1 = args.get(1);

        match cmd {
            "connect" => {
                self.connect(arg1).await?;
            }
            "disconnect" => {
                self.disconnect().await?;
            }
            "get" | "?" => {
                self.gpv(arg1).await?;
            }
            "set" => {
                self.spv(arg1).await?;
            }
            "add" => {
                self.aobj(arg1).await?;
            }
            "ls" => {
                self.list(arg1).await?;
            }
            "cd" => {
                self.change_directory(arg1).await?;
            }
            "upgrade" => {
                self.upgrade(arg1).await?;
            }
            "help" => {
                self.help();
            }
            "exit" => self.exit = true,
            "" => {}
            _ => {
                self.parse_objpath(cmd).await?;
            }
        }

        Ok(())
    }

    fn cmdname_suggestions(&mut self) -> Vec<String> {
        let mut suggestions = vec![
            String::from("help "),
            String::from("exit "),
            String::from("ls "),
            String::from("cd "),
        ];
        if self.connectedto.is_some() {
            suggestions.push(String::from("disconnect "));
            suggestions.push(String::from("get "));
            suggestions.push(String::from("set "));
            suggestions.push(String::from("upgrade "));
            suggestions.push(String::from("add "));
        } else {
            suggestions.push(String::from("connect "));
        }
        suggestions
    }

    async fn connect_suggestions(&mut self) -> Result<Vec<String>> {
        let mut suggestions = Vec::<String>::new();
        let response = self.sendrequest(api::Command::List).await?;

        if let api::Response::List(list) = response {
            for cpe in list {
                suggestions.push(cpe.sn.clone());
            }
        }
        Ok(suggestions)
    }

    async fn getset_suggestions(&mut self, args: &[String]) -> Result<Vec<String>> {
        let mut suggestions = Vec::<String>::new();
        if self.connectedto.is_none() {
            return Ok(suggestions);
        }
        let relpath = args.last().unwrap();
        let path = self.abspath(relpath);
        let objpath = Self::objpath(&path);
        let gpn = api::GetParameterNames {
            name: objpath,
            next_level: true,
        };
        let response = self
            .sendrequest(api::Command::GetParameterNames(gpn))
            .await?;
        if let api::Response::GetParameterNames(list) = response {
            for param in list {
                if let Some(relpath) = self.relpath(&param.name) {
                    suggestions.push(String::from(relpath));
                }
            }
        }
        Ok(suggestions)
    }

    async fn autocomplete(&mut self, args: &Vec<String>) -> Result<Vec<String>> {
        let mut suggestions;

        if args.len() <= 1 {
            suggestions = self.cmdname_suggestions();
            if let Ok(mut objects) = self.getset_suggestions(args).await {
                suggestions.append(&mut objects);
            };
        } else {
            let cmd = args[0].as_str();
            suggestions = match self.connectedto {
                Some(_) => match cmd {
                    "get" | "set" | "cd" | "ls" => self.getset_suggestions(args).await?,
                    "help" | "exit" | "disconnect" | "upgrade" => Vec::<String>::new(),
                    _ => Vec::<String>::new(),
                },
                None => match cmd {
                    "cd" | "connect" => self.connect_suggestions().await?,
                    _ => Vec::<String>::new(),
                },
            };
        }

        let current_word = args.last().unwrap().as_str();

        let mut list = Vec::<String>::new();
        for suggestion in suggestions {
            if suggestion.starts_with(current_word) {
                list.push(suggestion);
            }
        }

        Ok(list)
    }

    async fn main(&mut self) -> Result<()> {
        println!("Welcome to acscli");
        println!("Type 'help' to list the available commands");

        self.update_prompt();
        loop {
            let action = self.cli.getaction().await?;
            match action {
                Action::Command(args) => {
                    if let Err(err) = self.parse(&args).await {
                        println!("Error: {:?}", err);
                    }
                }
                Action::AutoComplete(args) => match self.autocomplete(&args).await {
                    Ok(words) => {
                        if let Err(err) = self.cli.autocomplete(&words) {
                            println!("Error: {:?}", err);
                        }
                    }
                    Err(err) => {
                        println!("Error: {:?}", err);
                    }
                },
            }
            if self.exit {
                break;
            }
        }
        Ok(())
    }
}

#[tokio::main]
pub async fn main() -> Result<()> {
    let mut acscli = AcsCli::new()?;
    acscli.main().await?;
    Ok(())
}
