//! Parsing for sing-box compatible predefined DNS resource records.
//!
//! ACP transports every record as either its zone-file text representation or
//! a base64 encoded, standalone wire-format RR.  The runtime resolver only
//! exposes an address lookup API, so records are fully validated here while
//! only A and AAAA records from the answer section are projected to addresses.

use std::io;
use std::net::IpAddr;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use hickory_resolver::proto::rr::{Name, RData, Record};
use hickory_resolver::proto::serialize::binary::{BinDecodable, BinDecoder};
use hickory_resolver::proto::serialize::txt::Parser;

/// A DNS message cannot carry more than 65,535 bytes.  Text/base64 has a
/// modest allowance for encoding overhead, while the aggregate cap prevents a
/// policy update from using unbounded memory before the record-count check.
const MAX_PREDEFINED_RECORDS: usize = 256;
const MAX_RECORD_INPUT_BYTES: usize = 96 * 1024;
const MAX_RECORD_WIRE_BYTES: usize = u16::MAX as usize;
const MAX_TOTAL_RECORD_INPUT_BYTES: usize = 1024 * 1024;

/// Validate predefined DNS sections and return the A/AAAA subset visible to
/// the address-only lookup API.
///
/// Records in `authority` and `additional` are validated but intentionally do
/// not affect the returned addresses, matching sing-box's `Lookup` behavior.
pub fn parse_predefined_lookup_addresses(
    answer: &[String],
    authority: &[String],
    additional: &[String],
) -> io::Result<Vec<IpAddr>> {
    let record_count = answer
        .len()
        .checked_add(authority.len())
        .and_then(|count| count.checked_add(additional.len()))
        .ok_or_else(|| invalid_record("predefined DNS record count overflow"))?;
    if record_count > MAX_PREDEFINED_RECORDS {
        return Err(invalid_record(format!(
            "predefined DNS response has {record_count} records; limit is {MAX_PREDEFINED_RECORDS}"
        )));
    }

    let mut total_input_bytes = 0usize;
    let mut addresses = Vec::new();
    for (section, records, extract_addresses) in [
        ("answer", answer, true),
        ("ns", authority, false),
        ("extra", additional, false),
    ] {
        for (index, value) in records.iter().enumerate() {
            total_input_bytes = total_input_bytes
                .checked_add(value.len())
                .ok_or_else(|| invalid_record("predefined DNS record size overflow"))?;
            if total_input_bytes > MAX_TOTAL_RECORD_INPUT_BYTES {
                return Err(invalid_record(format!(
                    "predefined DNS response exceeds {MAX_TOTAL_RECORD_INPUT_BYTES} input bytes"
                )));
            }
            let record = parse_record(value).map_err(|error| {
                invalid_record(format!(
                    "invalid {section}[{index}] resource record: {error}"
                ))
            })?;
            if extract_addresses {
                match &record.data {
                    RData::A(address) => addresses.push(IpAddr::V4(address.0)),
                    RData::AAAA(address) => addresses.push(IpAddr::V6(address.0)),
                    _ => {}
                }
            }
        }
    }
    Ok(addresses)
}

fn parse_record(value: &str) -> io::Result<Record> {
    if value.is_empty() {
        return Err(invalid_record("record must not be empty"));
    }
    if value.len() > MAX_RECORD_INPUT_BYTES {
        return Err(invalid_record(format!(
            "record is {} bytes; limit is {MAX_RECORD_INPUT_BYTES}",
            value.len()
        )));
    }

    // sing-box first attempts standard base64.  A successful decode followed
    // by an invalid RR is an error, rather than falling back to text parsing.
    if let Ok(wire) = BASE64.decode(value) {
        if wire.len() > MAX_RECORD_WIRE_BYTES {
            return Err(invalid_record(format!(
                "decoded wire record is {} bytes; limit is {MAX_RECORD_WIRE_BYTES}",
                wire.len()
            )));
        }
        let mut decoder = BinDecoder::new(&wire);
        let record = Record::read(&mut decoder)
            .map_err(|error| invalid_record(format!("invalid base64 wire RR: {error}")))?;
        if !decoder.is_empty() {
            return Err(invalid_record(format!(
                "base64 wire RR has {} trailing bytes",
                decoder.len()
            )));
        }
        return Ok(record);
    }

    // Keep the pre-policy Rust configuration's bare-IP shorthand compatible.
    // ACP/sing-box emits full RRs, so this is an additive local extension.
    if let Ok(address) = value.parse::<IpAddr>() {
        let data = match address {
            IpAddr::V4(address) => RData::A(address.into()),
            IpAddr::V6(address) => RData::AAAA(address.into()),
        };
        return Ok(Record::from_rdata(Name::root(), 0, data));
    }

    if value.contains(['\r', '\n']) {
        return Err(invalid_record("text form must contain exactly one RR line"));
    }
    let (_, sets) = Parser::new(value, None, Some(Name::root()))
        .parse()
        .map_err(|error| invalid_record(format!("invalid textual RR: {error}")))?;
    let mut records = sets.values().flat_map(|set| set.records_without_rrsigs());
    let record = records
        .next()
        .cloned()
        .ok_or_else(|| invalid_record("text form did not contain a resource record"))?;
    if records.next().is_some() {
        return Err(invalid_record(
            "text form must contain exactly one resource record",
        ));
    }
    Ok(record)
}

fn invalid_record(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use hickory_resolver::proto::rr::rdata::{A, AAAA};
    use hickory_resolver::proto::serialize::binary::{BinEncodable, BinEncoder};

    use super::*;

    fn wire_record(record: &Record) -> String {
        let mut bytes = Vec::new();
        record.emit(&mut BinEncoder::new(&mut bytes)).unwrap();
        BASE64.encode(bytes)
    }

    #[test]
    fn extracts_only_answer_a_and_aaaa_from_full_text_records() {
        let answers = vec![
            "example.test. 60 IN A 192.0.2.8".to_string(),
            "example.test. 60 IN TXT \"ignored\"".to_string(),
            "example.test. 60 IN AAAA 2001:db8::8".to_string(),
        ];
        let authority = vec!["example.test. 60 IN NS ns.example.test.".to_string()];
        let additional = vec!["ns.example.test. 60 IN A 192.0.2.53".to_string()];

        assert_eq!(
            parse_predefined_lookup_addresses(&answers, &authority, &additional).unwrap(),
            [
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 8)),
                IpAddr::V6("2001:db8::8".parse().unwrap()),
            ]
        );
    }

    #[test]
    fn parses_base64_wire_records_and_rejects_trailing_bytes() {
        let a = Record::from_rdata(
            Name::from_ascii("example.test.").unwrap(),
            60,
            RData::A(A(Ipv4Addr::new(198, 51, 100, 7))),
        );
        let aaaa = Record::from_rdata(
            Name::from_ascii("example.test.").unwrap(),
            60,
            RData::AAAA(AAAA(Ipv6Addr::LOCALHOST)),
        );
        let answers = vec![wire_record(&a), wire_record(&aaaa)];
        assert_eq!(
            parse_predefined_lookup_addresses(&answers, &[], &[]).unwrap(),
            [
                IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)),
                IpAddr::V6(Ipv6Addr::LOCALHOST),
            ]
        );

        let mut invalid = BASE64.decode(&answers[0]).unwrap();
        invalid.push(0);
        let error =
            parse_predefined_lookup_addresses(&[BASE64.encode(invalid)], &[], &[]).unwrap_err();
        assert!(error.to_string().contains("trailing bytes"));
    }

    #[test]
    fn preserves_bare_ip_compatibility_and_bounds_record_count() {
        let answers = vec!["203.0.113.9".to_string(), "2001:db8::9".to_string()];
        assert_eq!(
            parse_predefined_lookup_addresses(&answers, &[], &[]).unwrap(),
            [
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
                IpAddr::V6("2001:db8::9".parse().unwrap()),
            ]
        );

        let too_many = vec!["example.test. 0 IN TXT \"x\"".to_string(); 257];
        let error = parse_predefined_lookup_addresses(&too_many, &[], &[]).unwrap_err();
        assert!(error.to_string().contains("limit is 256"));
    }
}
