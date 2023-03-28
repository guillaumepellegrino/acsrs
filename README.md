# ACRS
A simple ACS written in Rust.

You can get or set datamodel from any CPE managed by this ACS with a simple curl command.

Supported features are:
- Zero-conf server: The server tries to configure itself securely at first start.
- HTTP, HTTPs and authentication support.
- ACS configuration and connected CPEs are persistent.
- GetParameterValues and SetParameterValues.

Some limitations are:
- There are no notifications mechanism implemented.
- It may not be fully compliant with TR-069 standard.
- syslog support not yet implemented.
- Logging is quite messy.
- No cli or web interfaces implemented.

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

# Usage
## List managed CPEs by this ACS
```
curl 127.0.0.1:8080/list
```

## Send a GetParameterValue to the specified CPE
```
curl 127.0.0.1:8080/gpv/{CPE_SERIAL_NUMBER} -d Device.ManagementServer.
```

## Send a SetParameterValue to the specified CPE
```
curl 127.0.0.1:8080/spv/{CPE_SERIAL_NUMBER} -d "Device.WiFi.NeighboringWiFiDiagnostic.DiagnosticsState<string>=Requested"
```

## Send a GetParameterValue to the specified CPE, requesting multiple objects
```
curl 127.0.0.1:8080/gpv/{CPE_SERIAL_NUMER} -d Device.ManagementServer.;Device.Time.
```

