use std::collections::HashMap;
use std::error::Error;
use std::fs::File;
use std::io::{BufReader, Write};
use std::iter::Map;

use serde::Deserialize;

use crate::{CommandArgConfig, process_cfg_str};
use crate::retroguard::{SRG_CLIENT, SRG_SERVER};

const MAPPING_CLASSES_CSV: &str = "mappings/classes.csv";
const MAPPING_METHODS_CSV: &str = "mappings/methods.csv";
const MAPPING_FIELDS_CSV: &str = "mappings/fields.csv";

const MAPPING_SAFFX_CLIENT: &str = "%temp%/minecraft.saffx";
const MAPPING_SAFFX_SERVER: &str = "%temp%/minecraft_server.saffx";

#[derive(Debug, Deserialize)]
struct ClassMapping {
    name: String,
    notch: String,
    supername: String,
    package: String,
    side: String,
}

#[derive(Debug, Deserialize)]
struct MethodFieldMapping {
    searge: String,
    name: String,
    notch: String,
    sig: String,
    notchsig: String,
    classname: String,
    classnotch: String,
    package: String,
    side: String,
    method: bool,
}

fn clean_base_mc_mappings(notch: &str, side_str: &str) -> Option<&str> {
    match notch.as_str() {
        "Start" => None,
        "Minecraft" | "MinecraftApplet" | "MinecraftServer" => {
            Some("net/minecraft/" + side_str + "/" + notch)
        },
        _ => Some(notch),
    }
}

pub fn write_srg_from_csv(client: boolean, config: &CommandArgConfig) -> Result<(), dyn Error> {
    let (mut packages, mut classes, mut methods, mut fields): HashMap<&str, &str> = HashMap::new();

    packages.insert(".", "net/minecraft/src");
    packages.insert("net", "net");
    packages.insert("net/minecraft", "net/minecraft");

    if client {
        packages.insert("net/minecraft/client", "net/minecraft/client");
        packages.insert("net/minecraft/isom", "net/minecraft/isom");
    } else {
        packages.insert("net/minecraft/server", "net/minecraft/server");
    }

    let side: &str = if client { "0" } else { "1" };
    let side_str: &str = if client { "client" } else { "server" };

    let class_csv_file: File = File::create(process_cfg_str(MAPPING_CLASSES_CSV, &config, None))?;
    let class_csv_reader: BufReader<File> = BufReader::new(class_csv_file);

    let mut class_csv: csv::Reader<BufReader<File>> = csv::Reader::from_reader(class_csv_reader);

    for class_result in class_csv.deserialize() {
        let class_mapping: ClassMapping = class_result?;

        if class_mapping.side != side { continue; }

        clean_base_mc_mappings(notch, side_str).and_then(|notch_row| {
            classes.insert(notch_row, format!("{}/{}", class_mapping.package, class_mapping.name));
            None
        });
    }

    let methods_csv_file: File = File::create(process_cfg_str(MAPPING_METHODS_CSV, &config, None))?;
    let methods_csv_reader: BufReader<File> = BufReader::new(methods_csv_file);

    let fields_csv_file: File = File::create(process_cfg_str(MAPPING_METHODS_CSV, &config, None))?;
    let fields_csv_reader: BufReader<File> = BufReader::new(fields_csv_file);

    let mut methods_csv: csv::Reader<BufReader<File>> = csv::Reader::from_reader(methods_csv_reader);
    let mut fields_csv: csv::Reader<BufReader<File>> = csv::Reader::from_reader(fields_csv_reader);

    let fields_map = methods_csv.deserialize().map(|res| {
        let mut mapping: MethodFieldMapping = res?;
        mapping.method = true;
        mapping
    }).zip(fields_csv);

    for fields_result in fields_map {
        let fields_mapping: MethodFieldMapping = fields_result?;

        if fields_mapping.side != side { continue; }

        clean_base_mc_mappings(notch, side_str).and_then(|notch_row| {
            if fields_mapping.method { methods } else { fields }
                    .insert(format!("{}/{} {}",
                                   methods_mapping.classnotch, methods_mapping.notch,
                                   methods_mapping.notchsig),
                           format!("{}/{}/{} {}",
                                   methods_mapping.package, methods_mapping.classname,
                                   methods_mapping.searge, methods_mapping.sig));
            None
        });
    }

    // Write to SRGS
    let srgs_base_path: &str = if client { SRG_CLIENT } else { SRG_SERVER };
    let srgs_path: String = process_cfg_str(srgs_base_path, &config, None);

    let mut srgs_out: File = File::create(srgs_path)?;

    let srgs_hash_map: HashMap<&str, &HashMap<&str, &str>> = [
        ("PK", packages),
        ("CL", classes),
        ("MD", methods),
        ("FD", fields),
    ].iter().clone().collect();

    for (key, map) in srgs_hash_map {
        for (m_key, m_val) in map {
            srgs_out.write(format!("{}: {} {}\r\n", key, m_key, m_val).as_bytes());
        }
    }

    Ok(())
}

pub fn create_saffx(client: bool, config: &CommandArgConfig) {
    let saffx_base_path: &str = if client { MAPPING_SAFFX_CLIENT } else { MAPPING_SAFFX_SERVER };
    let saffx_path: String = process_cfg_str(saffx_base_path, &config, None);

    let mut saffx_out: File = File::create(saffx_path)?;

    saffx_out.write("[OPTIONS]\n".as_bytes());
    saffx_out.write("strip_package net/minecraft/src\n\n".as_bytes());

    let class_csv_file: File = File::create(process_cfg_str(MAPPING_CLASSES_CSV, &config, None))?;
    let class_csv_reader: BufReader<File> = BufReader::new(class_csv_file);

    let methods_csv_file: File = File::create(process_cfg_str(MAPPING_METHODS_CSV, &config, None))?;
    let methods_csv_reader: BufReader<File> = BufReader::new(methods_csv_file);

    let fields_csv_file: File = File::create(process_cfg_str(MAPPING_METHODS_CSV, &config, None))?;
    let fields_csv_reader: BufReader<File> = BufReader::new(fields_csv_file);

    let mut class_csv: csv::Reader<BufReader<File>> = csv::Reader::from_reader(class_csv_reader);
    let mut fields_csv: csv::Reader<BufReader<File>> = csv::Reader::from_reader(fields_csv_reader);
    let mut methods_csv: csv::Reader<BufReader<File>> = csv::Reader::from_reader(methods_csv_reader);

    let side: &str = if client { "0" } else { "1" };

    saffx_out.write("[CLASSES]\n".as_bytes());

    for class_result in class_csv.deserialize() {
        let class_mapping: ClassMapping = class_result?;

        if class_mapping.name == "Start" || class_mapping.side != side {
            continue;
        }

        saffx_out.write(format!("{}/{} {}\n",
                                class_mapping.package, class_mapping.name,
                                class_mapping.notch).as_bytes());
    }

    saffx_out.write("[FIELDS]\n".as_bytes());

    for fields_result in fields_csv.deserialize() {
        let fields_mapping: MethodFieldMapping = fields_result?;

        if fields_mapping.name == "Start" || fields_mapping.side != side {
            continue;
        }

        saffx_out.write(format!("{}/{}/{} {}\n",
                                fields_mapping.package, fields_mapping.classname,
                                fields_mapping.name, fields_mapping.notch).as_bytes());
    }

    saffx_out.write("[METHODS]\n".as_bytes());

    for methods_result in methods_csv.deserialize() {
        let methods_mapping: MethodFieldMapping = methods_result?;

        if methods_mapping.name == "Start" || methods_mapping.side != side {
            continue;
        }

        saffx_out.write(format!("{}/{}/{} {} {}\n",
                                methods_mapping.package, methods_mapping.classname,
                                methods_mapping.name, methods_mapping.notchsig,
                                methods_mapping.notch).as_bytes());
    }

}