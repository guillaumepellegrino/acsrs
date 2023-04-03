use eyre::{Result, eyre};
use inquire::Text;
use inquire::ui::RenderConfig;
use inquire::ui::Styled;
use inquire::CustomUserError;

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

pub async fn main() -> Result<()> {
    let mut cli = Cli::new();
    cli.evlp().await?;
    Ok(())
}
