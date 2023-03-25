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
    pub text: u32,

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
            }
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
    pub fn get(self: &Self, name: &str) -> Option<&ParameterValue> {
        for pv in &self.parameter_values {
            if pv.name == name {
                return Some(pv);
            }
        }
        return None;
    }

    pub fn get_value(self: &Self, name: &str) -> Option<&str> {
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
        Self {
            max_envelopes: 1,
        }
    }
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
    pub fn push(self: &mut Self, name: &str) -> &mut Self {
        self.parameter_names.string.push(String::from(name));
        self.parameter_names.array_type = format!("xsd:string[{}]", self.parameter_names.string.len());
        self
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
    pub fn push(self: &mut Self, pv: ParameterValue) -> &mut Self {
        self.parameter_list.parameter_values.push(pv);
        let len = self.parameter_list.parameter_values.len();
        self.parameter_list.array_type = format!("cwmp:ParameterValueStruct[{}]", len);
        self
    }
}

#[derive(Debug, PartialEq, Default, Deserialize, Serialize)]
pub struct SetParameterValuesResponse {
    #[serde(rename = "Status")]
    pub status: i32,
}

#[derive(Debug, PartialEq, Default, Deserialize, Serialize)]
pub struct Body {
    #[serde(rename = "Inform")]
    #[serde(default)]
    pub inform: Vec<Inform>,

    #[serde(rename(serialize = "cwmp:InformResponse", deserialize = "InformResponse"))]
    #[serde(default)]
    pub inform_response: Vec<InformResponse>,

    #[serde(rename(serialize = "cwmp:GetParameterValues", deserialize = "GetParameterValues"))]
    #[serde(default)]
    pub gpv: Vec<GetParameterValues>,

    #[serde(rename(serialize = "cwmp:GetParameterValuesResponse", deserialize = "GetParameterValuesResponse"))]
    #[serde(default)]
    pub gpv_response: Vec<GetParameterValuesResponse>,

    #[serde(rename(serialize = "cwmp:SetParameterValues", deserialize = "SetParameterValues"))]
    #[serde(default)]
    pub spv: Vec<SetParameterValues>,

    #[serde(rename(serialize = "cwmp:SetParameterValuesResponse", deserialize = "SetParameterValuesResponse"))]
    #[serde(default)]
    pub spv_response: Vec<SetParameterValuesResponse>,
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
    pub fn new(id: u32) -> Self {
        let mut root = Self::default();
        root.header.id.text = id;
        root.header.id.must_understand = 1;
        root.xmlns_soap = String::from("http://schemas.xmlsoap.org/soap/encoding/");
        root.xmlns_xsd = String::from("http://www.w3.org/2001/XMLSchema");
        root.xmlns_cwmp = String::from("urn:dslforum-org:cwmp-1-0");
        root.xmlns_soapenv = String::from("http://schemas.xmlsoap.org/soap/envelope/");
        root.xmlns_xsi = String::from("http://www.w3.org/2001/XMLSchema-instance");
        root
    }

    pub fn add_inform_response(self: &mut Self) -> &mut InformResponse {
        self.body.inform_response.push(InformResponse::default());
        self.body.inform_response.first_mut().unwrap()
    }

    pub fn add_gpv(self: &mut Self) -> &mut GetParameterValues {
        self.body.gpv.push(GetParameterValues::default());
        self.body.gpv.first_mut().unwrap()
    }

    pub fn add_spv(self: &mut Self, parameter_key: u64) -> &mut SetParameterValues {
        let spv = SetParameterValues {
            parameter_list: ParameterList::default(),
            parameter_key: parameter_key,
        };
        self.body.spv.push(spv);
        self.body.spv.first_mut().unwrap()
    }

    pub fn id(self: &Self) -> u32 {
        self.header.id.text
    }

    pub fn inform(self: &Self) -> Option<&Inform> {
        self.body.inform.first()
    }
}

#[test]
fn test_bootstrap() {
    let xml: String = std::fs::read_to_string("test/bootstrap.xml").unwrap()
        .parse().unwrap();

    let bootstrap: Envelope = quick_xml::de::from_str(&xml).unwrap();
    println!("bootstrap = {:?}", bootstrap);

    assert_eq!(bootstrap.header.id.text, 515);
    let inform = bootstrap.inform().unwrap();
    assert_eq!(inform.device_id.manufacturer, "$MANUFACTURER");
    assert_eq!(inform.device_id.oui, "CAFE12");
    assert_eq!(inform.device_id.product_class, "$PRODUCT_CLASS");
    assert_eq!(inform.device_id.serial_number, "$SERIAL_NUMBER");

    {
        let ipaddress = ParameterValue::new(
            "Device.IP.Interface.1.IPv4Address.1.IPAddress", "xsd:string", "192.168.1.1");
        assert!(inform.parameter_list.parameter_values.contains(&ipaddress));
    }
    {
        let connreq_url = ParameterValue::new(
            "Device.ManagementServer.ConnectionRequestURL",
            "xsd:string",
            "http://192.168.1.1:7547/rnmDInfGzCpBvacM");
        assert!(inform.parameter_list.parameter_values.contains(&connreq_url));
    }
}

#[test]
fn test_inform_response() {
    let mut envelope = Envelope::new(2);
    envelope.add_inform_response();
    let value = quick_xml::se::to_string(&envelope).unwrap();
    let expected: String = std::fs::read_to_string("test/inform_response.xml").unwrap().parse().unwrap();
    assert_eq!(value, expected.trim());
}

#[test]
fn test_gpv() {
    let mut envelope = Envelope::new(2);
    let gpv = envelope.add_gpv();
    gpv.push("Device.");

    let value = quick_xml::se::to_string(&envelope).unwrap();
    let expected: String = std::fs::read_to_string("test/gpv.xml").unwrap().parse().unwrap();
    assert_eq!(value, expected.trim());
}

#[test]
fn test_spv() {
    let mut envelope = Envelope::new(2);
    let spv = envelope.add_spv(2302518885);
    spv.push(ParameterValue::new("Device.ManagementServer.Enable", "xsd:boolean", "1"));

    let value = quick_xml::se::to_string(&envelope).unwrap();
    let expected: String = std::fs::read_to_string("test/spv.xml").unwrap().parse().unwrap();
    assert_eq!(value, expected.trim());
}

