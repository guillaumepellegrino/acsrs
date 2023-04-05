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

use eyre::{Result, eyre};
use inquire::Text;
use inquire::ui::RenderConfig;
use inquire::ui::Styled;
use inquire::CustomUserError;
use termios::*;




// TODO: Implement a more UNIX like command-line cli
struct Cli {
    quit: bool,
    host: String,
    client: reqwest::Client,
    connectedto: Option<String>,
}

fn suggester(input: &str) -> Result<Vec<String>, CustomUserError> {
    let suggestions = [
        "help",
        "quit",
        "list",
        "connect ",
        "disconnect",
        "get ",
        "set ",
    ];
    let mut list = Vec::<String>::new();
    for suggestion in suggestions {
        if suggestion.contains(input) {
            list.push(String::from(suggestion));
        }
    }

    Ok(list)
}

impl Cli {
    fn new() -> Self {
        Self {
            quit: false,
            host: String::from("http://127.0.0.1:8000"),
            client: reqwest::Client::new(),
            connectedto: None,
        }
    }

    async fn connect(self: &mut Self, serial_number: Option<&str>) -> Result<()> {
        let serial_number = serial_number.ok_or(eyre!("Missing Serial Number argument"))?;
        println!("Connect to {}", serial_number);

        /*
        let url = format!("{}/connect/{}", self.host, serial_number);
        let res = self.client.post(&url).send().await?;
        let content = res.text().await?;
        println!("{}", content);
        */
        self.connectedto = Some(String::from(serial_number));
        Ok(())
    }

    async fn disconnect(self: &mut Self) -> Result<()> {
        self.connectedto = None;
        Ok(())
    }

    async fn get(self: &mut Self, path: Option<&str>) -> Result<()> {
        let serial_number = match &self.connectedto {
            Some(value) => value,
            None => {return Err(eyre!("Not connected !"));},
        };
        let path = path.ok_or(eyre!("Missing path argument"))?;
        let url = format!("{}/gpv/{}", self.host, serial_number);
        let res = self.client.post(&url)
            .body(String::from(path))
            .send().await?;
        let content = res.text().await?;
        println!("{}", content);

        Ok(())
    }

    async fn set(self: &mut Self, path: Option<&str>) -> Result<()> {
        let serial_number = match &self.connectedto {
            Some(value) => value,
            None => {return Err(eyre!("Not connected !"));},
        };
        let path = path.ok_or(eyre!("Missing path argument"))?;
        let url = format!("{}/spv/{}", self.host, serial_number);
        let res = self.client.post(&url)
            .body(String::from(path))
            .send().await?;
        let content = res.text().await?;
        println!("{}", content);

        Ok(())
    }

    async fn change_directory(self: &mut Self) -> Result<()> {
        Ok(())
    }

    async fn list(self: &Self) -> Result<()> {
        let url = format!("{}/list", self.host);
        let res = self.client.post(&url).send().await?;
        let content = res.text().await?;
        println!("{}", content);
        Ok(())
    }

    fn help(self: &Self) {
        println!("acscli: interactive cli for ACSRS");
        println!("Availables commands:");
        println!(" - help: Display this help");
        println!(" - quit: Quit the application");
        println!(" - list: Show connected CPEs to this ACS");
        println!(" - connect [SN] : Connect to CPE specified by this Serial Number");
        println!(" - disconnect :  Disconnect from the current CPE");
        println!(" - get [path] : Get object or parameter value");
        println!(" - set [path]<type>=value : Set Parameter value");
        //println!(" - upgrade [filename] : Upgrade CPE to provided firmware");
    }

    async fn evlp_one(self: &mut Self) -> Result<()> {
        let prefix = match &self.connectedto {
            Some(connectedto) => format!("{} $", connectedto),
            None => String::from("$"),
        };

        let render_config = RenderConfig::default()
            .with_prompt_prefix(Styled::new(""));
        let line = Text::new(&prefix)
            .with_render_config(render_config)
            .with_autocomplete(suggester)
            .prompt()?;

        let mut split = line.split(' ');
        let cmd  = split.next().ok_or(eyre!("No command provided"))?;
        let arg1 = split.next();

        match cmd {
            "c"|"connect" => {self.connect(arg1).await?;},
            "d"|"disconnect" => {self.disconnect().await?;},
            "g"|"get" => {self.get(arg1).await?;},
            "s"|"set" => {self.set(arg1).await?;},
            "l"|"list" => {self.list().await?;},
            "cd" => {self.change_directory().await?;},
            "h"|"help" => {self.help();},
            "q"|"quit" => {self.quit = true},
            "" => {},
            _ => {return Err(eyre!("Unknown command '{}'", cmd));},
        }

        Ok(())
    }

    async fn evlp(self: &mut Self) -> Result<()> {
        println!("Welcome to acscli");
        println!("Type 'help' to list the available commands");
        loop {
            if let Err(err) = self.evlp_one().await {
                println!("Error: {:?}", err);
            }
            if self.quit {
                break;
            }
        }
        Ok(())
    }
}


use tokio::io::{Stdin, stdin, BufReader, AsyncReadExt};
use std::io::Write;
use std::io::stdout;

pub struct Console {
    saved_termios: Termios,
    reader: BufReader<Stdin>,
    quit: bool,
    cmd: String,
    history: Vec<String>,
}

impl Console {
    pub fn new() -> Result<Self> {
        let fd = 0;
        let saved = Termios::from_fd(fd)?;
        let mut termios = saved;
        termios.c_lflag &= !(ECHO | ECHONL | ICANON);
        tcsetattr(fd, TCSANOW, &termios)?;

        Ok(Self {
            saved_termios: saved,
            reader: BufReader::new(stdin()),
            quit: false,
            cmd: String::new(),
            history: Vec::<String>::new(),
        })
    }

    fn args(self: &Self) -> Vec<String> {
        let mut args = Vec::<String>::new();
        let mut arg = String::new();
        let mut is_string = false;
        let mut is_escaped = false;
        for c in self.cmd.chars() {
            if is_escaped {
                arg.push(c);
                is_escaped = false;
                continue;
            }
            match c {
                '\\' => { is_escaped = true; },
                '"' => { is_string = !is_string; },
                ' ' => {
                        match is_string {
                            true => { arg.push(c); },
                            false => { args.push(arg.clone()); arg.clear(); },
                        };
                    },
                _ => { arg.push(c); }
            }
        }
        args.push(arg);
        args
    }

    fn reset(self: &mut Self) {
        self.cmd.clear();
        print!("> ");
        stdout().flush();
    }

    async fn history_prev(self: &mut Self) -> Result<()> {
        println!("History PREV");
        Ok(())
    }

    async fn history_next(self: &mut Self) -> Result<()> {
        println!("History NEXT");
        Ok(())
    }

    async fn escape(self: &mut Self) -> Result<()> {
        let c = self.reader.read_u8().await?;
        if c != 0x5B {
            return Ok(());
        }
        let c = self.reader.read_u8().await?;
        match c {
            0x41 => { // UP
                self.history_prev().await?;
            },
            0x42 => { // LOW
                self.history_next().await?;
            },
            0x43 => { // RIGHT

            },
            0x44 => { // LEFT

            },
            _ => {},
        }
        Ok(())
    }

    async fn addchar(self: &mut Self, c: char) -> Result<()> {
        print!("{}", c);
        stdout().flush();
        self.cmd.push(c);
        Ok(())
    }

    async fn delchar(self: &mut Self) -> Result<()> {
        print!("\x08 \x08");
        stdout().flush();
        Ok(())
    }

    async fn eol(self: &mut Self) -> Result<()> {
        println!("");
        println!("Args: {:?}", self.args());

        self.history.push(self.cmd.clone());
        self.reset();
        Ok(())
    }

    async fn autocomplete(self: &mut Self) -> Result<()> {
        println!("autocomplete: ");
        Ok(())
    }

    async fn evlp_one(self: &mut Self) -> Result<()> {
        let c = self.reader.read_u8().await?;

        match c {
            0x1B => { // ESC (escap)
                self.escape().await?;
            },
            0x7F => { // DEL
                self.delchar().await?;
            },
            b'\n' => {
                self.eol().await?;
            },
            b'\t' => {
                self.autocomplete().await?;
            },
            b'q' => {
                self.quit = true;
            },
            _ => {
                self.addchar(c as char).await?;
            }
        }

        Ok(())
    }

    pub async fn evlp_main(self: &mut Self) -> Result<()> {
        self.reset();
        while self.quit == false {
            self.evlp_one().await?;
        }

        Ok(())
    }
}

impl Drop for Console {
    fn drop(self: &mut Self) {
        println!("Cleanup console");
        let fd = 0;
        if let Err(e) = tcsetattr(fd, TCSANOW, &self.saved_termios) {
            println!("Failed to restore terminal config: {:?}", e);
        }
    }
}

pub async fn main() -> Result<()> {
    // TODO: to be used in combinaison with clap ?
    let mut console = Console::new()?;
    console.evlp_main().await?;

    //let mut cli = Cli::new();
    //cli.evlp().await?;
    Ok(())
}
