use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, PartialEq, Default, Clone, Deserialize, Serialize)]
pub struct GetParameterNames {
    pub name: String,
    pub next_level: bool,
}

#[derive(Debug, PartialEq, Default, Clone, Deserialize, Serialize)]
pub struct GetParameterNamesResponse {
    pub name: String,
    pub writable: bool,
}

#[derive(Debug, PartialEq, Default, Clone, Deserialize, Serialize)]
pub struct GetParameterValues {
    pub r#type: String,
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
pub struct SetParameterValuesResponse {
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
pub struct ErrorResponse {
    pub description: String,
}

#[derive(Debug, PartialEq, Clone, Deserialize, Serialize)]
pub enum Command {
    GetParameterNames(GetParameterNames),
    GetParameterValues(Vec<GetParameterValues>),
    SetParameterValues(Vec<SetParameterValues>),
    Upgrade(Upgrade),
    List(),
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
    SetParameterValues(SetParameterValuesResponse),
    Upgrade(UpgradeResponse),
    Error(ErrorResponse),
}
