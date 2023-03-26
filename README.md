# ACRS
A simple ACS written in Rust. It can be used for testing purpose.

# Build ACS
```
git clone git@github.com:guillaumepellegrino/acrs.git
cd acsrs
cargo build --release
```

# Run ACS
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

