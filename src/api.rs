use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, PartialEq, Default, Clone, Deserialize, Serialize)]
pub struct GetParameterNames {
    pub name: String,
    #[serde(default)]
    pub next_level: bool,
}

#[derive(Debug, PartialEq, Default, Clone, Deserialize, Serialize)]
pub struct GetParameterNamesResponse {
    pub name: String,
    pub writable: bool,
}

#[derive(Debug, PartialEq, Default, Clone, Deserialize, Serialize)]
pub struct GetParameterValues {
    pub name: String,
}

#[derive(Debug, PartialEq, Default, Clone, Deserialize, Serialize)]
pub struct GetParameterValuesResponse {
    pub r#type: String,
    pub name: String,
    pub value: String,
}

#[derive(Debug, PartialEq, Default, Clone, Deserialize, Serialize)]
pub struct SetParameterValues {
    pub r#type: String,
    pub name: String,
    pub value: String,
}

#[derive(Debug, PartialEq, Default, Clone, Deserialize, Serialize)]
pub struct AddObject {
    pub object_name: String,
}

#[derive(Debug, PartialEq, Default, Clone, Deserialize, Serialize)]
pub struct AddObjectResponse {
    pub instance_number: u32,
    pub status: bool,
}

#[derive(Debug, PartialEq, Default, Clone, Deserialize, Serialize)]
pub struct DeleteObject {
    pub object_name: String,
}

#[derive(Debug, PartialEq, Default, Clone, Deserialize, Serialize)]
pub struct DeleteObjectResponse {
    pub status: bool,
}

#[derive(Debug, PartialEq, Default, Clone, Deserialize, Serialize)]
pub struct Upgrade {
    pub file_name: String,
}

#[derive(Debug, PartialEq, Default, Clone, Deserialize, Serialize)]
pub struct UpgradeResponse {
    pub status: bool,
}

#[derive(Debug, PartialEq, Default, Clone, Deserialize, Serialize)]
#[allow(clippy::upper_case_acronyms)]
pub struct CPE {
    pub sn: String,
    pub url: String,
    pub username: String,
    pub password: String,
}

#[derive(Debug, PartialEq, Clone, Deserialize, Serialize)]
pub enum Event {
    Boostrap,
    Boot,
    Periodic,
    Scheduled,
    ValueChange,
    Kicked,
    ConnectionRequest,
    TransferComplete,
    DiagnosticsComplete,
    RequestDownload,
    AutonomousTransferComplete,
    MReboot,
    MScheduleInform,
    MDownload,
    MUpload,
}

#[derive(Debug, PartialEq, Default, Clone, Deserialize, Serialize)]
pub struct InformParameter {
    pub r#type: String,
    pub name: String,
    pub value: String,
}

#[derive(Debug, PartialEq, Default, Clone, Deserialize, Serialize)]
pub struct Inform {
    pub manufacturer: String,
    pub oui: String,
    pub product_class: String,
    pub serial_number: String,
    pub events: Vec<Event>,
    pub parameters: Vec<InformParameter>,
}

#[derive(Debug, PartialEq, Default, Clone, Deserialize, Serialize)]
pub struct ErrorResponse {
    pub status: u16,
    pub description: String,
}

#[derive(Debug, PartialEq, Clone, Deserialize, Serialize)]
pub enum Command {
    GetParameterNames(GetParameterNames),
    GetParameterValues(Vec<GetParameterValues>),
    SetParameterValues(Vec<SetParameterValues>),
    AddObject(AddObject),
    DeleteObject(DeleteObject),
    Upgrade(Upgrade),
    List,
    Monitor,
}

#[derive(Debug, PartialEq, Clone, Deserialize, Serialize)]
pub struct Request {
    #[serde(default)]
    pub serial_number: String,
    pub command: Command,
}

#[derive(Debug, PartialEq, Clone, Deserialize, Serialize)]
pub enum Response {
    GetParameterNames(Vec<GetParameterNamesResponse>),
    GetParameterValues(Vec<GetParameterValuesResponse>),
    SetParameterValues(bool),
    AddObject(AddObjectResponse),
    DeleteObject(DeleteObjectResponse),
    Upgrade(UpgradeResponse),
    List(Vec<CPE>),
    Error(ErrorResponse),
    Monitor(Vec<Inform>),
}

impl Response {
    #[allow(dead_code)]
    pub fn error(status: u16, description: &str) -> Self {
        Response::Error(ErrorResponse {
            status,
            description: String::from(description),
        })
    }
}
