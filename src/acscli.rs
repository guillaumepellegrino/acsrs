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

use eyre::{eyre, Result};
mod cli;
use crate::cli::{Cli, Action};

struct AcsCli {
    cli: Cli,
    exit: bool,
    host: String,
    client: reqwest::Client,
    connectedto: Option<String>,
    directory: String,
}

impl AcsCli {
    fn new() -> Result<Self> {
        Ok(Self {
            cli: Cli::new()?,
            exit: false,
            host: String::from("http://127.0.0.1:8000"),
            client: reqwest::Client::new(),
            connectedto: None,
            directory: String::new(),
        })
    }

    fn update_prompt(self: &mut Self) {
        let prompt = match &self.connectedto {
            Some(connectedto) => format!("> {}:{} ", connectedto, self.directory),
            None => String::from("> "),
        };
        self.cli.setprompt(&prompt);
    }

    async fn connect(self: &mut Self, args: &Vec<String>) -> Result<()> {
        let serial_number = args.get(1);
        let serial_number = serial_number.ok_or(eyre!("Missing Serial Number argument"))?;
        println!("Connect to {}", serial_number);

        self.connectedto = Some(String::from(serial_number));
        self.update_prompt();
        Ok(())
    }

    async fn disconnect(self: &mut Self) -> Result<()> {
        self.connectedto = None;
        self.directory = String::new();
        self.update_prompt();
        Ok(())
    }

    async fn get(self: &mut Self, cmd: &str, args: &Vec<String>) -> Result<()> {
        let serial_number = match &self.connectedto {
            Some(value) => value,
            None => {return Err(eyre!("Not connected !"));},
        };
        let relpath = match args.get(1) {
            Some(relpath) => relpath.as_str(),
            None => "",
        };
        let abspath = self.abspath(relpath);
        let url = format!("{}/{}/{}", self.host, cmd, serial_number);
        let res = self.client.post(&url)
            .body(abspath)
            .send().await?;
        let content = res.text().await?;
        println!("{}", content);

        Ok(())
    }

    async fn set(self: &mut Self, args: &Vec<String>) -> Result<()> {
        let serial_number = match &self.connectedto {
            Some(value) => value,
            None => {return Err(eyre!("Not connected !"));},
        };
        let path = args.get(1);
        let path = path.ok_or(eyre!("Missing path argument"))?;
        let url = format!("{}/spv/{}", self.host, serial_number);
        let res = self.client.post(&url)
            .body(String::from(path))
            .send().await?;
        let content = res.text().await?;
        println!("{}", content);

        Ok(())
    }

    fn abspath(self: &Self, relpath: &str) -> String {
        format!("{}{}", self.directory, relpath)
    }

    fn relpath<'a>(self: &Self, abspath: &'a str) -> Option<&'a str> {
        abspath.strip_prefix(&self.directory)
    }

    fn objpath(path: &str) -> String {
        match path.rsplit_once('.') {
            Some((obj, _)) => format!("{}.", obj),
            None => String::new(),
        }
    }

    async fn change_directory(self: &mut Self, args: &Vec<String>) -> Result<()> {
        if self.connectedto == None {
            println!("You are not connected to a CPE\nPlease use 'connect [SERIAL_NUMBER]'");
            return Ok(());
        }

        let path = match args.get(1) {
            Some(path) => path,
            None => {
                self.directory = String::new();
                self.update_prompt();
                return Ok(());
            },
        };

        let mut current: Vec<&str> = self.directory.split(".").collect();
        current.pop();

        match path.as_str() {
            ""|"/" => {
                current.clear();
            },
            ".." => {
                current.pop();
            },
            _ => {
                for dir in path.split(".") {
                    match dir {
                        "" => {},
                        _ => {
                            current.push(dir);
                        },
                    }
                }
            },
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

    async fn list_cpes(self: &Self) -> Result<()> {
        let url = format!("{}/list", self.host);
        let res = self.client.post(&url).send().await?;
        let content = res.text().await?;
        println!("{}", content);
        Ok(())
    }

    async fn list_parameters(self: &mut Self, args: &Vec<String>) -> Result<()> {
        self.get("gpn", args).await
    }

    async fn list(self: &mut Self, args: &Vec<String>) -> Result<()> {
        match self.connectedto {
            Some(_) => self.list_parameters(args).await,
            None => self.list_cpes().await,
        }
    }

    fn help(self: &Self) {
        println!("acscli: interactive cli for ACSRS");
        println!("Global commands:");
        println!(" - help: Display this help");
        println!(" - exit: Exit this application");
        println!("");
        println!("Availables command when disconnected:");
        println!(" - ls: List connected CPEs to this ACS");
        println!(" - cd|connect [SN] : Connect to CPE specified by this Serial Number");
        println!("");
        println!("Availables command when connected to a CPE:");
        println!(" - disconnect :  Disconnect from the current CPE");
        println!(" - ls [path]: List Parameters under current object");
        println!(" - cd [path]: Change directory");
        println!(" - get [path] : Get object or parameter value");
        println!(" - set [path]<type>=value : Set Parameter value");
        //println!(" - upgrade [filename] : Upgrade CPE to provided firmware");
    }

    async fn parse(self: &mut Self, args: &Vec<String>) -> Result<()> {
        let cmd  = args[0].as_str();

        match cmd {
            "connect" => {self.connect(args).await?;},
            "disconnect" => {self.disconnect().await?;},
            "get" => {self.get("gpv", args).await?;},
            "set" => {self.set(args).await?;},
            "ls" => {self.list(args).await?;},
            "cd" => {self.change_directory(args).await?;},
            "help" => {self.help();},
            "exit" => {self.exit = true},
            "" => {},
            _ => {return Err(eyre!("Unknown command '{}'", cmd));},
        }

        Ok(())
    }

    fn cmdname_suggestions(self: &mut Self) -> Vec<String> {
        let mut suggestions = Vec::<String>::new();
        suggestions.push(String::from("help "));
        suggestions.push(String::from("exit "));
        if self.connectedto != None {
            suggestions.push(String::from("disconnect "));
            suggestions.push(String::from("get "));
            suggestions.push(String::from("set "));
            suggestions.push(String::from("cd "));
        }
        else {
            suggestions.push(String::from("ls "));
            suggestions.push(String::from("connect "));
        }
        suggestions
    }

    async fn connect_suggestions(self: &mut Self) -> Result<Vec<String>> {
        let mut suggestions = Vec::<String>::new();
        let url = format!("{}/snlist", self.host);
        let res = self.client.post(&url).send().await?;
        let content = res.text().await?;
        for line in content.lines() {
            suggestions.push(String::from(line));
        }
        Ok(suggestions)
    }

    async fn getset_suggestions(self: &mut Self, args: &Vec<String>) -> Result<Vec<String>> {
        let mut suggestions = Vec::<String>::new();
        let sn = match &self.connectedto {
            Some(sn) => sn,
            None => {return Ok(suggestions);},
        };
        let relpath = args.last().unwrap();
        let path = self.abspath(&relpath);
        let objpath = Self::objpath(&path);
        let url = format!("{}/gpn/{}", self.host, sn);
        //println!("objpath={}", objpath);
        let res = self.client.post(&url)
            .body(objpath)
            .send().await?;
        let content = res.text().await?;

        for line in content.lines() {
            let path = match line.get(5..) {
                Some(path) => path,
                None => {continue;},
            };
            if let Some(relpath) = self.relpath(path) {
                //println!("path={}", path);
                suggestions.push(String::from(relpath));
            }
        }

        Ok(suggestions)
    }

    async fn autocomplete(self: &mut Self, args: &Vec<String>) -> Result<Vec<String>> {
        let suggestions;

        if args.len() <= 1 {
            suggestions = self.cmdname_suggestions();
        }
        else {
            let cmd = args[0].as_str();
            suggestions = match cmd {
                "connect" => self.connect_suggestions().await?,
                "get"|"set"|"cd" => self.getset_suggestions(args).await?,
                _ => Vec::<String>::new(),
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

    async fn main(self: &mut Self) -> Result<()> {
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
                Action::AutoComplete(args) => {
                    match self.autocomplete(&args).await {
                        Ok(words) => {
                            if let Err(err) = self.cli.autocomplete(&words) {
                                println!("Error: {:?}", err);
                            }
                        },
                        Err(err) => {
                            println!("Error: {:?}", err);
                        },
                    }
                }
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
