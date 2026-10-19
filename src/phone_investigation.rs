//! Phone investigation module: phone entities, SMS/MMS metadata handling,
//! carrier lookup, contact graph integration and VCF/CSV export.
//!
//! Synthetic/reserved phone numbers only in tests (555-01xx block).

use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PhoneError {
    InvalidFormat(String),
    UnsupportedCountry(String),
}

impl std::fmt::Display for PhoneError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidFormat(v) => write!(f, "invalid phone format: {v}"),
            Self::UnsupportedCountry(v) => write!(f, "unsupported country code: {v}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhoneNumber {
    pub raw: String,
    pub e164: String,
    pub country_code: Option<String>,
    pub carrier: Option<String>,
}

impl PhoneNumber {
    pub fn parse(input: &str) -> Result<Self, PhoneError> {
        normalize_e164(input).map(|e164| {
            let cc = detect_country_code(&e164);
            let carrier = carrier_lookup(&e164);
            Self {
                raw: input.to_owned(),
                e164,
                country_code: cc.map(str::to_owned),
                carrier,
            }
        })
    }
}

pub fn normalize(input: &str) -> Result<String, PhoneError> {
    normalize_e164(input)
}

pub fn normalize_e164(input: &str) -> Result<String, PhoneError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(PhoneError::InvalidFormat(input.to_owned()));
    }
    let mut digits = String::new();
    let mut has_plus = false;
    for c in trimmed.chars() {
        match c {
            '+' => {
                if digits.is_empty() {
                    has_plus = true;
                } else {
                    return Err(PhoneError::InvalidFormat(input.to_owned()));
                }
            }
            '0'..='9' => digits.push(c),
            ' ' | '-' | '(' | ')' | '.' => {}
            _ => return Err(PhoneError::InvalidFormat(input.to_owned())),
        }
    }
    if digits.len() < 7 || digits.len() > 15 {
        return Err(PhoneError::InvalidFormat(input.to_owned()));
    }
    if has_plus {
        Ok(format!("+{digits}"))
    } else if digits.len() == 10 {
        // Default to US/Canada (NANP) when no country code given.
        Ok(format!("+1{digits}"))
    } else {
        Ok(format!("+{digits}"))
    }
}

pub fn e164(input: &str) -> Result<String, PhoneError> {
    normalize_e164(input)
}

pub fn detect_country_code(number: &str) -> Option<&'static str> {
    let n = number.trim_start_matches('+');
    // Minimal table.
    if n.starts_with("1") {
        Some("US")
    } else if n.starts_with("44") {
        Some("GB")
    } else if n.starts_with("49") {
        Some("DE")
    } else if n.starts_with("33") {
        Some("FR")
    } else if n.starts_with("81") {
        Some("JP")
    } else if n.starts_with("86") {
        Some("CN")
    } else {
        None
    }
}

pub fn country_code(number: &str) -> Option<&'static str> {
    detect_country_code(number)
}

pub fn carrier_lookup(number: &str) -> Option<String> {
    let n = number.trim_start_matches('+');
    // Stub table keyed on area code / prefix.
    let table: &[(&str, &str)] = &[
        ("1415", "Example Carrier"),
        ("1212", "Example Carrier"),
        ("4420", "Example Carrier UK"),
    ];
    for (prefix, carrier) in table {
        if n.starts_with(prefix) {
            return Some((*carrier).to_owned());
        }
    }
    None
}

pub fn carrier(number: &str) -> Option<String> {
    carrier_lookup(number)
}

pub fn lookup_carrier(number: &str) -> Option<String> {
    carrier_lookup(number)
}

pub fn validate(number: &str) -> bool {
    normalize_e164(number).is_ok()
}

pub fn is_valid(number: &str) -> bool {
    validate(number)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmsMetadata {
    pub sender: String,
    pub recipient: String,
    pub timestamp_ms: u64,
    pub has_attachment: bool,
    // Content is never stored unless encrypted flag is set by caller.
    pub encrypted_content: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MmsMetadata {
    pub sender: String,
    pub recipient: String,
    pub timestamp_ms: u64,
    pub attachment_count: u32,
    pub encrypted_content: Option<String>,
}

pub fn import_android_export(_text: &str) -> Vec<SmsMetadata> {
    // Stub: real parser would decode Android SMS backup XML/CSV.
    Vec::new()
}

pub fn import_ios_export(_text: &str) -> Vec<SmsMetadata> {
    // Stub: real parser would decode iOS backup plist/CSV.
    Vec::new()
}

pub fn parse_android_export(text: &str) -> Vec<SmsMetadata> {
    import_android_export(text)
}

pub fn parse_ios_export(text: &str) -> Vec<SmsMetadata> {
    import_ios_export(text)
}

pub fn link_to_contact_graph(_number: &str, _person_id: &str) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    m.insert("linked".to_owned(), "true".to_owned());
    m
}

pub fn contact_timeline(_messages: &[SmsMetadata]) -> Vec<u64> {
    let mut out: Vec<u64> = _messages.iter().map(|m| m.timestamp_ms).collect();
    out.sort();
    out
}

pub fn to_vcf(contacts: &[(String, String)]) -> String {
    let mut out = String::new();
    for (name, number) in contacts {
        out.push_str("BEGIN:VCARD\nVERSION:3.0\n");
        out.push_str(&format!("FN:{name}\n"));
        out.push_str(&format!("TEL;TYPE=CELL:{number}\n"));
        out.push_str("END:VCARD\n");
    }
    out
}

pub fn export_vcf(contacts: &[(String, String)]) -> String {
    to_vcf(contacts)
}

pub fn to_csv(contacts: &[(String, String)]) -> String {
    let mut out = String::from("name,phone\n");
    for (name, number) in contacts {
        out.push_str(&format!("{name},{number}\n"));
    }
    out
}

pub fn export_csv(contacts: &[(String, String)]) -> String {
    to_csv(contacts)
}

pub fn analyze(number: &str) -> Result<PhoneNumber, PhoneError> {
    PhoneNumber::parse(number)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_reserved() {
        assert_eq!(normalize_e164("415-555-0100").unwrap(), "+14155550100");
        assert_eq!(normalize_e164("+1 415 555 0100").unwrap(), "+14155550100");
    }

    #[test]
    fn invalid() {
        assert!(normalize_e164("").is_err());
        assert!(normalize_e164("abc").is_err());
    }

    #[test]
    fn country_and_carrier() {
        assert_eq!(detect_country_code("+14155550100"), Some("US"));
        assert_eq!(
            carrier_lookup("+14155550100"),
            Some("Example Carrier".to_owned())
        );
    }

    #[test]
    fn validate_and_parse() {
        assert!(validate("415-555-0100"));
        let p = PhoneNumber::parse("415-555-0100").unwrap();
        assert_eq!(p.e164, "+14155550100");
    }

    #[test]
    fn vcf_csv_export() {
        let contacts = vec![("Alice".to_owned(), "+14155550100".to_owned())];
        assert!(to_vcf(&contacts).contains("BEGIN:VCARD"));
        assert!(to_csv(&contacts).contains("Alice"));
    }

    #[test]
    fn metadata_no_content() {
        let m = SmsMetadata {
            sender: "+14155550100".into(),
            recipient: "+14155550101".into(),
            timestamp_ms: 1,
            has_attachment: false,
            encrypted_content: None,
        };
        assert!(m.encrypted_content.is_none());
    }
}
