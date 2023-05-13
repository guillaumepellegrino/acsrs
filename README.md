# ACSRS
A simple ACS written in Rust.

You can get or set datamodel from any CPE managed by this ACS with a simple curl command.

Supported features are:
- Zero-conf server: The server tries to configure itself securely at first start.
- HTTP, HTTPs and authentication support.
- ACS configuration and connected CPEs are persistent.
- CLI with advanced auto-completion to interact with CPEs.
- GetParameterValues, SetParameterValues, Upgrade.

Some limitations are:
- There are no notifications mechanism implemented.
- It may not be fully compliant with TR-069 standard.
- syslog support not yet implemented.
- Logging is quite messy.

# Install ACSRS
The application can be installed directly from cargo
```
cargo install acsrs
```

# Run ACSRS
Simply start the application without any arguments:
```
acsrs
```
It will auto-configure itself by generating new user, password, certificate and CA. Everything is available under `$HOME/.acrs` directory and can be overrided. Some usefuls files are:
- config.toml : The ACS configuration.
- ca.pem : The certificate authority. Install this file on your CPEs to authenticate the ACS.
- identity.p12: The PKCS12 identity used by the ACS.
- cert.pem: The ACS Public Certificate.

Note: The ACS Public Certificate Common Name (CN) is derived from your public IP Address by default.
It can be overrided by editing $HOME/.acsrs/config.toml and setting your hostname there. You can also disable there the auto-generation certificate mechanism if you wish to install your own certificates.

# Usage with acscli
acscli is an interactive UNIX cli for ACSRS

## Global commands:
 - help: Display this help
 - exit: Exit this application

## Availables command when disconnected:
 - ls: List connected CPEs to this ACS
 - cd|connect [SN] : Connect to CPE specified by this Serial Number

## Availables command when connected to a CPE:
 - disconnect :  Disconnect from the current CPE
 - ls [path]: List Parameters under current object
 - cd [path]: Change directory
 - get [path] | [path]? : Get object or parameter value
 - set [path]<type>=value | [path]<type>=value : Set Parameter value
 - upgrade [filename] : Upgrade CPE to provided firmware


# ACS Management APIs
ACS Server is manageable by default on http://127.0.0.1:8000/api url with JSON APIs.
JSON APIs are defined in https://github.com/guillaumepellegrino/acsrs/blob/master/src/api.rs
