# ACRS
A simple ACS written in Rust.

You can get or set datamodel from any CPE managed by this ACS with a simple curl command.

Supported features are:
- ACS configuration and connected CPEs are persistent
- ACS handle Authentication
- GetParameterValues
- SetParameterValues

Some limitations are:
- This ACS server is unsecure: HTTPs is not yet implemented
- SOAP errors are not forwarded to curl
- There are no notifications mechanism implemented
- It may not be fully compliant with TR-069 standard

# Build ACSRS
```
git clone git@github.com:guillaumepellegrino/acrs.git
cd acsrs
cargo build --release
```

# Run ACSRS
```
export ACS_USERNAME={username}
export ACS_PASSWORD={password}
./target/release/acsrs
```

# Usage
## List managed CPEs by this ACS
```
curl 127.0.0.1:8080/list
```

## Send a GetParameterValue to the specified CPE
```
curl 127.0.0.1:8080/gpv/{CPE_SERIAL_NUMER} -d Device.ManagementServer.
```

## Send a SetParameterValue to the specified CPE
```
curl 127.0.0.1:8080/spv/{CPE_SERIAL_NUMER} -d "Device.WiFi.NeighboringWiFiDiagnostic.DiagnosticsState<string>=Requested"
```

## Send a GetParameterValue to the specified CPE, requesting multiple objects
```
curl 127.0.0.1:8080/gpv/{CPE_SERIAL_NUMER} -d Device.ManagementServer.;Device.Time.
```

