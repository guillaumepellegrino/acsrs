# ACRS
A simple ACS written in Rust.

You can get or set datamodel from any CPE managed by this ACS with a simple curl command.

Supported features are:
- Zero-conf server: The server tries to configure itself securely at first start.
- HTTP, HTTPs and authentication support.
- ACS configuration and connected CPEs are persistent
- GetParameterValues and SetParameterValues with simple curl requests.

Some limitations are:
- There are no notifications mechanism implemented
- It may not be fully compliant with TR-069 standard
- syslog support not yet implemented
- logging is quite messy
- no cli or web interfaces implemented

# Build ACSRS
```
git clone git@github.com:guillaumepellegrino/acrs.git
cd acsrs
cargo build --release
```

# Run ACSRS
```
./target/release/acsrs
```

# Usage
## list managed cpes by this acs
```
curl 127.0.0.1:8080/list
```

## send a getparametervalue to the specified cpe
```
curl 127.0.0.1:8080/gpv/{cpe_serial_numer} -d device.managementserver.
```

## send a setparametervalue to the specified cpe
```
curl 127.0.0.1:8080/spv/{cpe_serial_numer} -d "device.wifi.neighboringwifidiagnostic.diagnosticsstate<string>=requested"
```

## Send a GetParameterValue to the specified CPE, requesting multiple objects
```
curl 127.0.0.1:8080/gpv/{CPE_SERIAL_NUMER} -d Device.ManagementServer.;Device.Time.
```

