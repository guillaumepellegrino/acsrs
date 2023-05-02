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
use eyre::Result;
use serde::{Deserialize, Serialize};
use std::io::Write;

#[derive(Debug, PartialEq, Default, Deserialize, Serialize)]
#[allow(clippy::upper_case_acronyms)]
pub struct CPE {
    pub serial_number: String,
    pub url: String,
    pub username: String,
    pub password: String,
}

#[derive(Debug, PartialEq, Default, Clone, Deserialize, Serialize)]
pub struct AcsConfig {
    pub hostname: String,
    pub username: String,
    pub password: String,
    pub autocert: bool,
    pub identity_password: String,
    pub secure_address: String,
    pub unsecure_address: String,
    pub management_address: String,
}

#[derive(Debug, PartialEq, Default, Deserialize, Serialize)]
pub struct Acs {
    pub config: AcsConfig,
    pub cpe: Vec<CPE>,
}

impl Acs {
    /**
     * Save ACS configuration to TOML file specified by path
     */
    pub fn save(&self, path: &std::path::Path) -> Result<()> {
        let mut file = std::fs::File::create(path)?;
        let string = toml::to_string(self)?;
        file.write_all(string.as_bytes())?;
        Ok(())
    }

    /**
     * Restore ACS configuration from TOML file specified by path
     */
    pub fn restore(path: &std::path::Path) -> Result<Acs> {
        let string = std::fs::read_to_string(path)?;
        let acs: Acs = toml::from_str(&string)?;
        Ok(acs)
    }
}
