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
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, PartialEq, Default, Deserialize, Serialize)]
pub struct ID {
    #[serde(rename = "$text")]
    pub text: String,

    #[serde(rename = "@soapenv:mustUnderstand")]
    #[serde(default)]
    must_understand: u32,
}

#[derive(Debug, PartialEq, Default, Deserialize, Serialize)]
pub struct Header {
    #[serde(rename(serialize = "cwmp:ID", deserialize = "ID"))]
    pub id: ID,
}

#[derive(Debug, PartialEq, Default, Deserialize, Serialize, Clone)]
pub struct DeviceId {
    #[serde(rename = "Manufacturer")]
    pub manufacturer: String,

    #[serde(rename = "OUI")]
    pub oui: String,

    #[serde(rename = "ProductClass")]
    pub product_class: String,

    #[serde(rename = "SerialNumber")]
    pub serial_number: String,
}

#[derive(Debug, PartialEq, Default, Deserialize, Serialize)]
pub struct EventStruct {
    #[serde(rename = "EventCode")]
    pub event_code: String,

    #[serde(rename = "CommandKey")]
    pub command_key: String,
}

#[derive(Debug, PartialEq, Default, Deserialize, Serialize)]
pub struct Event {
    #[serde(rename = "EventStruct")]
    #[serde(default)]
    pub event_struct: Vec<EventStruct>,
}

impl Event {
    pub fn contains(&self, event_code: &str) -> bool {
        for event in &self.event_struct {
            if event.event_code == event_code {
                return true;
            }
        }
        false
    }
}

#[derive(Debug, PartialEq, Default, Deserialize, Serialize)]
pub struct Value {
    #[serde(rename(serialize = "@xsi:type", deserialize = "@type"))]
    #[serde(default)]
    pub xsi_type: String,

    #[serde(rename = "$text")]
    #[serde(default)]
    pub text: String,
}

#[derive(Debug, PartialEq, Default, Deserialize, Serialize)]
pub struct ParameterValue {
    #[serde(rename = "Name")]
    pub name: String,

    #[serde(rename = "Value")]
    pub value: Value,
}

impl ParameterValue {
    pub fn new(name: &str, xsi_type: &str, value: &str) -> Self {
        Self {
            name: String::from(name),
            value: Value {
                xsi_type: String::from(xsi_type),
                text: String::from(value),
            },
        }
    }
}

#[derive(Debug, PartialEq, Default, Deserialize, Serialize)]
pub struct ParameterList {
    #[serde(rename(serialize = "@soap:arrayType", deserialize = "@arrayType"))]
    #[serde(default)]
    pub array_type: String,

    #[serde(rename = "ParameterValueStruct")]
    #[serde(default)]
    pub parameter_values: Vec<ParameterValue>,
}

impl ParameterList {
    pub fn get(&self, name: &str) -> Option<&ParameterValue> {
        self.parameter_values.iter().find(|&pv| pv.name == name)
    }

    pub fn get_value(&self, name: &str) -> Option<&str> {
        match self.get(name) {
            Some(pv) => Some(pv.value.text.as_str()),
            None => None,
        }
    }
}

#[derive(Debug, PartialEq, Default, Deserialize, Serialize)]
pub struct Inform {
    #[serde(rename = "DeviceId")]
    pub device_id: DeviceId,

    #[serde(rename = "Event")]
    #[serde(default)]
    pub event: Event,

    #[serde(rename = "ParameterList")]
    #[serde(default)]
    pub parameter_list: ParameterList,
}

#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub struct InformResponse {
    #[serde(rename = "MaxEnvelopes")]
    pub max_envelopes: u32,
}

impl Default for InformResponse {
    fn default() -> Self {
        Self { max_envelopes: 1 }
    }
}

#[derive(Debug, PartialEq, Default, Deserialize, Serialize)]
pub struct GetParameterNames {
    #[serde(rename = "ParameterPath")]
    #[serde(default)]
    pub parameter_path: String,

    #[serde(rename = "NextLevel")]
    #[serde(default)]
    pub next_level: u8,
}

#[derive(Debug, PartialEq, Default, Deserialize, Serialize)]
pub struct ParameterInfoStruct {
    #[serde(rename = "Name")]
    #[serde(default)]
    pub name: String,

    #[serde(rename = "Writable")]
    #[serde(default)]
    pub writable: u8,
}

#[derive(Debug, PartialEq, Default, Deserialize, Serialize)]
pub struct ParameterListInfo {
    #[serde(rename = "ParameterInfoStruct")]
    #[serde(default)]
    parameter_info: Vec<ParameterInfoStruct>,
}

#[derive(Debug, PartialEq, Default, Deserialize, Serialize)]
pub struct GetParameterNamesResponse {
    #[serde(rename = "ParameterList")]
    #[serde(default)]
    parameter_list: ParameterListInfo,
}

#[derive(Debug, PartialEq, Default, Deserialize, Serialize)]
pub struct ParameterNames {
    #[serde(rename = "@soap:arrayType")]
    #[serde(default)]
    array_type: String,

    #[serde(rename = "string")]
    pub string: Vec<String>,
}

#[derive(Debug, PartialEq, Default, Deserialize, Serialize)]
pub struct GetParameterValues {
    #[serde(rename = "ParameterNames")]
    #[serde(default)]
    pub parameter_names: ParameterNames,
}

impl GetParameterValues {
    pub fn push(&mut self, name: &str) -> &mut Self {
        self.parameter_names.string.push(String::from(name));
        self.parameter_names.array_type =
            format!("xsd:string[{}]", self.parameter_names.string.len());
        self
    }

    pub fn len(&self) -> usize {
        self.parameter_names.string.len()
    }
}

#[derive(Debug, PartialEq, Default, Deserialize, Serialize)]
pub struct GetParameterValuesResponse {
    #[serde(rename = "ParameterList")]
    #[serde(default)]
    pub parameter_list: ParameterList,
}

#[derive(Debug, PartialEq, Default, Deserialize, Serialize)]
pub struct SetParameterValues {
    #[serde(rename = "ParameterList")]
    pub parameter_list: ParameterList,

    #[serde(rename = "ParameterKey")]
    pub parameter_key: u64,
}

impl SetParameterValues {
    pub fn push(&mut self, pv: ParameterValue) -> &mut Self {
        self.parameter_list.parameter_values.push(pv);
        let len = self.parameter_list.parameter_values.len();
        self.parameter_list.array_type = format!("cwmp:ParameterValueStruct[{}]", len);
        self
    }

    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.parameter_list.parameter_values.len()
    }
}

#[derive(Debug, PartialEq, Default, Deserialize, Serialize)]
pub struct SetParameterValuesResponse {
    #[serde(rename = "Status")]
    pub status: i32,
}

#[derive(Debug, PartialEq, Default, Deserialize, Serialize)]
pub struct Download {
    #[serde(rename = "CommandKey")]
    pub command_key: Value,

    #[serde(rename = "FileType")]
    pub file_type: Value,

    #[serde(rename = "URL")]
    pub url: Value,

    #[serde(rename = "Username")]
    pub username: Value,

    #[serde(rename = "Password")]
    pub password: Value,

    #[serde(rename = "FileSize")]
    pub file_size: Value,

    #[serde(rename = "TargetFileName")]
    pub target_file_name: Value,

    #[serde(rename = "DelaySeconds")]
    pub delay_seconds: Value,

    #[serde(rename = "SuccessURL")]
    pub success_url: Value,

    #[serde(rename = "FailureURL")]
    pub failure_url: Value,
}

impl Download {
    #[allow(dead_code)]
    pub fn new() -> Self {
        let mut download = Download::default();
        download
            .set_command_key("")
            .set_file_type("")
            .set_url("")
            .set_username("")
            .set_password("")
            .set_file_size(0)
            .set_target_file_name("")
            .set_delay_seconds(0)
            .set_success_url("")
            .set_failure_url("");
        download
    }

    pub fn set_command_key(&mut self, value: &str) -> &mut Self {
        self.command_key = Value {
            xsi_type: String::from("xsd:string"),
            text: String::from(value),
        };
        self
    }

    pub fn set_file_type(&mut self, value: &str) -> &mut Self {
        self.file_type = Value {
            xsi_type: String::from("xsd:string"),
            text: String::from(value),
        };
        self
    }

    pub fn set_url(&mut self, value: &str) -> &mut Self {
        self.url = Value {
            xsi_type: String::from("xsd:string"),
            text: String::from(value),
        };
        self
    }

    pub fn set_username(&mut self, value: &str) -> &mut Self {
        self.username = Value {
            xsi_type: String::from("xsd:string"),
            text: String::from(value),
        };
        self
    }

    pub fn set_password(&mut self, value: &str) -> &mut Self {
        self.password = Value {
            xsi_type: String::from("xsd:string"),
            text: String::from(value),
        };
        self
    }

    pub fn set_file_size(&mut self, value: i64) -> &mut Self {
        self.file_size = Value {
            xsi_type: String::from("xsd:long"),
            text: format!("{}", value),
        };
        self
    }

    pub fn set_target_file_name(&mut self, value: &str) -> &mut Self {
        self.target_file_name = Value {
            xsi_type: String::from("xsd:string"),
            text: String::from(value),
        };
        self
    }

    pub fn set_delay_seconds(&mut self, value: i32) -> &mut Self {
        self.delay_seconds = Value {
            xsi_type: String::from("xsd:int"),
            text: format!("{}", value),
        };
        self
    }

    pub fn set_success_url(&mut self, value: &str) -> &mut Self {
        self.success_url = Value {
            xsi_type: String::from("xsd:string"),
            text: String::from(value),
        };
        self
    }

    pub fn set_failure_url(&mut self, value: &str) -> &mut Self {
        self.failure_url = Value {
            xsi_type: String::from("xsd:string"),
            text: String::from(value),
        };
        self
    }
}

#[derive(Debug, PartialEq, Default, Deserialize, Serialize)]
pub struct DownloadResponse {
    #[serde(rename = "Status")]
    pub status: String,

    #[serde(rename = "StartTime")]
    pub start_time: String,

    #[serde(rename = "CompleteTime")]
    pub complete_time: String,
}

#[derive(Debug, PartialEq, Default, Deserialize, Serialize)]
pub struct TransferComplete {
    #[serde(rename = "CommandKey")]
    pub command_key: String,

    #[serde(rename = "FaultStruct")]
    pub fault_struct: CwmpFault,

    #[serde(rename = "StartTime")]
    pub start_time: String,

    #[serde(rename = "CompleteTime")]
    pub complete_time: String,
}

#[derive(Debug, PartialEq, Default, Deserialize, Serialize)]
pub struct TransferCompleteResponse {}

#[derive(Debug, PartialEq, Default, Deserialize, Serialize)]
pub struct Reboot {
    #[serde(rename = "CommandKey")]
    pub command_key: Value,
}

impl Reboot {
    pub fn new(command_key: &str) -> Self {
        Self {
            command_key: Value {
                xsi_type: String::from("xsd:string"),
                text: String::from(command_key),
            },
        }
    }
}

#[derive(Debug, PartialEq, Default, Deserialize, Serialize)]
pub struct RebootResponse {}

#[derive(Debug, PartialEq, Default, Deserialize, Serialize)]
pub struct CwmpFault {
    #[serde(rename = "FaultCode")]
    #[serde(default)]
    pub faultcode: Value,

    #[serde(rename = "FaultString")]
    #[serde(default)]
    pub faultstring: Value,
}

#[derive(Debug, PartialEq, Default, Deserialize, Serialize)]
pub struct SoapFaultDetail {
    #[serde(rename(serialize = "cwmp:Fault", deserialize = "Fault"))]
    #[serde(default)]
    pub cwmpfault: CwmpFault,
}

#[derive(Debug, PartialEq, Default, Deserialize, Serialize)]
pub struct SoapFault {
    #[serde(rename = "faultcode")]
    #[serde(default)]
    pub faultcode: String,

    #[serde(rename = "faultstring")]
    #[serde(default)]
    pub faultstring: String,

    #[serde(rename = "detail")]
    #[serde(default)]
    pub detail: SoapFaultDetail,
}

#[derive(Debug)]
pub enum Kind {
    Inform,
    InformResponse,
    GetParameterNames,
    GetParameterNamesResponse,
    GetParameterValues,
    GetParameterValuesResponse,
    SetParameterValues,
    SetParameterValuesResponse,
    Download,
    DownloadResponse,
    Reboot,
    RebootResponse,
    TransferComplete,
    TransferCompleteResponse,
    Fault,
    Unknown,
}

#[derive(Debug, PartialEq, Default, Deserialize, Serialize)]
pub struct Body {
    #[serde(rename = "Inform")]
    #[serde(default)]
    pub inform: Vec<Inform>,

    #[serde(rename(serialize = "cwmp:InformResponse", deserialize = "InformResponse"))]
    #[serde(default)]
    pub inform_response: Vec<InformResponse>,

    #[serde(rename(
        serialize = "cwmp:GetParameterNames",
        deserialize = "GetParameterNames"
    ))]
    #[serde(default)]
    pub gpn: Vec<GetParameterNames>,

    #[serde(rename(
        serialize = "cwmp:GetParameterNamesResponse",
        deserialize = "GetParameterNamesResponse"
    ))]
    #[serde(default)]
    pub gpn_response: Vec<GetParameterNamesResponse>,

    #[serde(rename(
        serialize = "cwmp:GetParameterValues",
        deserialize = "GetParameterValues"
    ))]
    #[serde(default)]
    pub gpv: Vec<GetParameterValues>,

    #[serde(rename(
        serialize = "cwmp:GetParameterValuesResponse",
        deserialize = "GetParameterValuesResponse"
    ))]
    #[serde(default)]
    pub gpv_response: Vec<GetParameterValuesResponse>,

    #[serde(rename(
        serialize = "cwmp:SetParameterValues",
        deserialize = "SetParameterValues"
    ))]
    #[serde(default)]
    pub spv: Vec<SetParameterValues>,

    #[serde(rename(
        serialize = "cwmp:SetParameterValuesResponse",
        deserialize = "SetParameterValuesResponse"
    ))]
    #[serde(default)]
    pub spv_response: Vec<SetParameterValuesResponse>,

    #[serde(rename(serialize = "cwmp:Download", deserialize = "Download"))]
    #[serde(default)]
    pub download: Vec<Download>,

    #[serde(rename(serialize = "cwmp:DownloadResponse", deserialize = "DownloadResponse"))]
    #[serde(default)]
    pub download_response: Vec<DownloadResponse>,

    #[serde(rename(serialize = "cwmp:TransferComplete", deserialize = "TransferComplete"))]
    #[serde(default)]
    pub transfer_complete: Vec<TransferComplete>,

    #[serde(rename(
        serialize = "cwmp:TransferCompleteResponse",
        deserialize = "TransferCompleteResponse"
    ))]
    #[serde(default)]
    pub transfer_complete_response: Vec<TransferCompleteResponse>,

    #[serde(rename(serialize = "cwmp:Reboot", deserialize = "Reboot"))]
    #[serde(default)]
    pub reboot: Vec<Reboot>,

    #[serde(rename(serialize = "cwmp:RebootResponse", deserialize = "RebootResponse"))]
    #[serde(default)]
    pub reboot_response: Vec<RebootResponse>,

    #[serde(rename(serialize = "soapenv:Fault", deserialize = "Fault"))]
    #[serde(default)]
    pub fault: Vec<SoapFault>,
}

#[derive(Debug, PartialEq, Default, Deserialize, Serialize)]
#[serde(rename(serialize = "soapenv:Envelope", deserialize = "Envelope"))]
pub struct Envelope {
    #[serde(rename = "@xmlns:soap")]
    #[serde(default)]
    xmlns_soap: String,

    #[serde(rename = "@xmlns:xsd")]
    #[serde(default)]
    xmlns_xsd: String,

    #[serde(rename = "@xmlns:cwmp")]
    #[serde(default)]
    xmlns_cwmp: String,

    #[serde(rename = "@xmlns:soapenv")]
    #[serde(default)]
    xmlns_soapenv: String,

    #[serde(rename = "@xmlns:xsi")]
    #[serde(default)]
    xmlns_xsi: String,

    #[serde(rename(serialize = "soapenv:Header", deserialize = "Header"))]
    pub header: Header,

    #[serde(rename(serialize = "soapenv:Body", deserialize = "Body"))]
    pub body: Body,
}

impl Envelope {
    pub fn new(id: &str) -> Self {
        let mut root = Self::default();
        root.header.id.text = String::from(id);
        root.header.id.must_understand = 1;
        root.xmlns_soap = String::from("http://schemas.xmlsoap.org/soap/encoding/");
        root.xmlns_xsd = String::from("http://www.w3.org/2001/XMLSchema");
        root.xmlns_cwmp = String::from("urn:dslforum-org:cwmp-1-0");
        root.xmlns_soapenv = String::from("http://schemas.xmlsoap.org/soap/envelope/");
        root.xmlns_xsi = String::from("http://www.w3.org/2001/XMLSchema-instance");
        root
    }

    pub fn kind(&self) -> Kind {
        if self.body.inform.first().is_some() {
            Kind::Inform
        } else if self.body.inform_response.first().is_some() {
            Kind::InformResponse
        } else if self.body.gpn.first().is_some() {
            Kind::GetParameterNames
        } else if self.body.gpn_response.first().is_some() {
            Kind::GetParameterNamesResponse
        } else if self.body.gpv.first().is_some() {
            Kind::GetParameterValues
        } else if self.body.gpv_response.first().is_some() {
            Kind::GetParameterValuesResponse
        } else if self.body.spv.first().is_some() {
            Kind::SetParameterValues
        } else if self.body.spv_response.first().is_some() {
            Kind::SetParameterValuesResponse
        } else if self.body.download.first().is_some() {
            Kind::Download
        } else if self.body.download_response.first().is_some() {
            Kind::DownloadResponse
        } else if self.body.transfer_complete.first().is_some() {
            Kind::TransferComplete
        } else if self.body.transfer_complete_response.first().is_some() {
            Kind::TransferCompleteResponse
        } else if self.body.reboot.first().is_some() {
            Kind::Reboot
        } else if self.body.reboot_response.first().is_some() {
            Kind::RebootResponse
        } else if self.body.fault.first().is_some() {
            Kind::Fault
        } else {
            Kind::Unknown
        }
    }

    pub fn add_inform_response(&mut self) -> &mut InformResponse {
        self.body.inform_response.push(InformResponse::default());
        self.body.inform_response.first_mut().unwrap()
    }

    pub fn add_transfer_complete_response(&mut self) -> &mut TransferCompleteResponse {
        self.body
            .transfer_complete_response
            .push(TransferCompleteResponse::default());
        self.body.transfer_complete_response.first_mut().unwrap()
    }

    pub fn add_gpn(&mut self, path: &str, next_level: bool) -> &mut GetParameterNames {
        self.body.gpn.push(GetParameterNames {
            parameter_path: String::from(path),
            next_level: next_level as u8,
        });
        self.body.gpn.first_mut().unwrap()
    }

    pub fn add_gpv(&mut self) -> &mut GetParameterValues {
        self.body.gpv.push(GetParameterValues::default());
        self.body.gpv.first_mut().unwrap()
    }

    pub fn add_spv(&mut self, parameter_key: u64) -> &mut SetParameterValues {
        let spv = SetParameterValues {
            parameter_list: ParameterList::default(),
            parameter_key,
        };
        self.body.spv.push(spv);
        self.body.spv.first_mut().unwrap()
    }

    #[allow(dead_code)]
    pub fn add_download(&mut self) -> &mut Download {
        self.body.download.push(Download::new());
        self.body.download.first_mut().unwrap()
    }

    #[allow(dead_code)]
    pub fn add_reboot(&mut self, command_key: &str) -> &mut Reboot {
        self.body.reboot.push(Reboot::new(command_key));
        self.body.reboot.first_mut().unwrap()
    }

    pub fn id(&self) -> &str {
        &self.header.id.text
    }

    pub fn inform(&self) -> Option<&Inform> {
        self.body.inform.first()
    }
}

impl std::fmt::Display for Envelope {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        if let Some(fault) = self.body.fault.first() {
            write!(
                f,
                "{} - {}",
                fault.detail.cwmpfault.faultcode.text, fault.detail.cwmpfault.faultstring.text
            )
        } else if let Some(response) = self.body.gpn_response.first() {
            for pn in &response.parameter_list.parameter_info {
                if pn.writable == 1 {
                    writeln!(f, "<r-> {}", pn.name)?;
                } else {
                    writeln!(f, "<rw> {}", pn.name)?;
                }
            }
            return write!(f, "");
        } else if let Some(response) = self.body.gpv_response.first() {
            for pv in &response.parameter_list.parameter_values {
                writeln!(f, "{}={}", pv.name, pv.value.text)?;
            }
            return write!(f, "");
        } else if let Some(response) = self.body.spv_response.first() {
            return write!(f, "Status: {}", response.status);
        } else if let Some(response) = self.body.download_response.first() {
            return write!(f, "Status: {}", response.status);
        } else {
            return write!(f, "Empty response");
        }
    }
}

#[test]
fn test_bootstrap() {
    let xml: String = std::fs::read_to_string("test/bootstrap.xml")
        .unwrap()
        .parse()
        .unwrap();

    let bootstrap: Envelope = quick_xml::de::from_str(&xml).unwrap();
    println!("bootstrap = {:?}", bootstrap);

    assert_eq!(bootstrap.id(), "515");
    let inform = bootstrap.inform().unwrap();
    assert_eq!(inform.device_id.manufacturer, "$MANUFACTURER");
    assert_eq!(inform.device_id.oui, "CAFE12");
    assert_eq!(inform.device_id.product_class, "$PRODUCT_CLASS");
    assert_eq!(inform.device_id.serial_number, "$SERIAL_NUMBER");

    {
        let ipaddress = ParameterValue::new(
            "Device.IP.Interface.1.IPv4Address.1.IPAddress",
            "xsd:string",
            "192.168.1.1",
        );
        assert!(inform.parameter_list.parameter_values.contains(&ipaddress));
    }
    {
        let connreq_url = ParameterValue::new(
            "Device.ManagementServer.ConnectionRequestURL",
            "xsd:string",
            "http://192.168.1.1:7547/rnmDInfGzCpBvacM",
        );
        assert!(inform
            .parameter_list
            .parameter_values
            .contains(&connreq_url));
    }
}

#[test]
fn test_transfer_complete() {
    let xml: String = std::fs::read_to_string("test/transfer_complete.xml")
        .unwrap()
        .parse()
        .unwrap();

    let transfer_complete: Envelope = quick_xml::de::from_str(&xml).unwrap();
    println!("transfer_complete = {:?}", transfer_complete);
    assert_eq!(transfer_complete.id(), "test1234");

    let body = &transfer_complete.body.transfer_complete[0];
    assert_eq!(body.command_key, "upgrade");
    assert_eq!(body.fault_struct.faultcode.text, "9015");
    assert_eq!(body.fault_struct.faultstring.text, "Server not found");
}

#[test]
fn test_inform_response() {
    let mut envelope = Envelope::new("2");
    envelope.add_inform_response();
    let value = quick_xml::se::to_string(&envelope).unwrap();
    let expected: String = std::fs::read_to_string("test/inform_response.xml")
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(value, expected.trim());
}

#[test]
fn test_gpn() {
    let mut envelope = Envelope::new("2");
    envelope.add_gpn("Device.", false);
    let value = quick_xml::se::to_string(&envelope).unwrap();
    let expected: String = std::fs::read_to_string("test/gpn.xml")
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(value, expected.trim());
}

#[test]
fn test_gpv() {
    let mut envelope = Envelope::new("2");
    let gpv = envelope.add_gpv();
    gpv.push("Device.");

    let value = quick_xml::se::to_string(&envelope).unwrap();
    let expected: String = std::fs::read_to_string("test/gpv.xml")
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(value, expected.trim());
}

#[test]
fn test_spv() {
    let mut envelope = Envelope::new("2");
    let spv = envelope.add_spv(2302518885);
    spv.push(ParameterValue::new(
        "Device.ManagementServer.Enable",
        "xsd:boolean",
        "1",
    ));

    let value = quick_xml::se::to_string(&envelope).unwrap();
    let expected: String = std::fs::read_to_string("test/spv.xml")
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(value, expected.trim());
}

#[test]
fn test_download() {
    let mut envelope = Envelope::new("2");
    let download = envelope.add_download();
    download
        .set_command_key("FirmwareUpgrade")
        .set_file_type("1 Firmware Upgrade Image")
        .set_url("http://192.168.1.100/firmware.img")
        .set_username("acsrs")
        .set_password("acsrs")
        .set_file_size(64000000)
        .set_target_file_name("firmware.img")
        .set_delay_seconds(0)
        .set_success_url("success")
        .set_failure_url("failure");

    let value = quick_xml::se::to_string(&envelope).unwrap();
    let expected: String = std::fs::read_to_string("test/download.xml")
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(value, expected.trim());
}

#[test]
fn test_reboot() {
    let mut envelope = Envelope::new("2");
    envelope.add_reboot("123456");

    let value = quick_xml::se::to_string(&envelope).unwrap();
    let expected: String = std::fs::read_to_string("test/reboot.xml")
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(value, expected.trim());
}
