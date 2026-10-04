use std::collections::BTreeMap;
use std::net::IpAddr;

pub fn endpoint_id(host: &str, port: u16, transport: &str) -> String {
    let canonical = host.to_ascii_lowercase();
    let input = format!("endpoint:{transport}:{canonical}:{port}");
    format!("endpoint_{:016x}", fnv(&input))
}

pub fn service_id(endpoint: &str, protocol: &str) -> String {
    let input = format!("service:{endpoint}:{protocol}");
    format!("service_{:016x}", fnv(&input))
}

pub fn hostname_id(name: &str) -> String {
    let input = format!("hostname:{}", name.to_ascii_lowercase());
    format!("hostname_{:016x}", fnv(&input))
}

pub fn certificate_id(fingerprint_sha256: &str) -> String {
    let normalized: String = fingerprint_sha256
        .chars()
        .filter(|c| *c != ':')
        .collect::<String>()
        .to_ascii_lowercase();
    format!("cert_{normalized}")
}

pub fn ssh_key_id(fingerprint_sha256: &str) -> String {
    let normalized: String = fingerprint_sha256
        .chars()
        .filter(|c| *c != ':')
        .collect::<String>()
        .to_ascii_lowercase();
    format!("sshkey_{normalized}")
}

pub fn software_id(vendor: Option<&str>, product: &str, version: Option<&str>) -> String {
    let input = format!(
        "software:{}:{}:{}",
        vendor.unwrap_or("*").to_ascii_lowercase(),
        product.to_ascii_lowercase(),
        version.unwrap_or("*")
    );
    format!("software_{:016x}", fnv(&input))
}

fn fnv(input: &str) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in input.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

pub fn public_entity_id(kind: &str, canonical_value: &str) -> String {
    let kind = kind.trim().to_ascii_lowercase();
    let canonical = canonical_value.trim().to_ascii_lowercase();
    format!("{kind}_{:016x}", fnv(&format!("{kind}:{canonical}")))
}

pub fn canonical_host(ip: &Option<IpAddr>, host: &str) -> String {
    match ip {
        Some(addr) => addr.to_string(),
        None => host.to_ascii_lowercase(),
    }
}

#[derive(Debug, Clone, Default)]
pub struct AssetRegistry {
    endpoints: BTreeMap<String, String>,
    services: BTreeMap<String, String>,
}

impl AssetRegistry {
    pub fn endpoint(&mut self, host: &str, port: u16, transport: &str) -> String {
        let key = format!("{}:{port}:{transport}", host.to_ascii_lowercase());
        if let Some(id) = self.endpoints.get(&key) {
            return id.clone();
        }
        let id = endpoint_id(host, port, transport);
        self.endpoints.insert(key, id.clone());
        id
    }

    pub fn service(&mut self, endpoint: &str, protocol: &str) -> String {
        let key = format!("{endpoint}:{protocol}");
        if let Some(id) = self.services.get(&key) {
            return id.clone();
        }
        let id = service_id(endpoint, protocol);
        self.services.insert(key, id.clone());
        id
    }

    pub fn len(&self) -> usize {
        self.endpoints.len() + self.services.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_identity_ignores_case_and_scheme_noise() {
        assert_eq!(
            endpoint_id("Example.TEST", 80, "tcp"),
            endpoint_id("example.test", 80, "tcp")
        );
        assert_ne!(
            endpoint_id("example.test", 80, "tcp"),
            endpoint_id("example.test", 443, "tcp")
        );
        assert_ne!(
            endpoint_id("example.test", 80, "tcp"),
            endpoint_id("example.test", 80, "udp")
        );
    }

    #[test]
    fn service_identity_is_endpoint_plus_protocol() {
        let endpoint = endpoint_id("example.test", 443, "tcp");
        let first = service_id(&endpoint, "https");
        assert_eq!(first, service_id(&endpoint, "https"));
        assert_ne!(first, service_id(&endpoint, "http"));
        assert!(first.starts_with("service_"));
    }

    #[test]
    fn version_changes_keep_service_entity() {
        let endpoint = endpoint_id("example.test", 443, "tcp");
        assert_eq!(
            service_id(&endpoint, "https"),
            service_id(&endpoint, "https")
        );
    }

    #[test]
    fn certificate_and_ssh_key_ids_are_stable() {
        assert_eq!(
            certificate_id("AB:CD"),
            certificate_id("ab:cd"),
            "fingerprint normalization must be case/colon insensitive"
        );
        assert!(ssh_key_id("AB:CD").starts_with("sshkey_"));
    }

    #[test]
    fn software_identity_normalizes_case() {
        assert_eq!(
            software_id(Some("Apache"), "HTTPD", Some("2.4")),
            software_id(Some("apache"), "httpd", Some("2.4"))
        );
        assert_ne!(
            software_id(Some("apache"), "httpd", Some("2.4")),
            software_id(Some("apache"), "httpd", Some("2.5"))
        );
    }

    #[test]
    fn registry_dedups() {
        let mut registry = AssetRegistry::default();
        let first = registry.endpoint("Example.TEST", 80, "tcp");
        assert_eq!(first, registry.endpoint("example.test", 80, "tcp"));
        let service = registry.service(&first, "http");
        assert_eq!(service, registry.service(&first, "http"));
        assert_eq!(registry.len(), 2);
    }

    #[test]
    fn ipv6_endpoint_is_canonical() {
        let id = endpoint_id("::1", 80, "tcp");
        assert!(id.starts_with("endpoint_"));
        assert_ne!(id, endpoint_id("127.0.0.1", 80, "tcp"));
    }

    #[test]
    fn public_entity_identity_ignores_display_case() {
        assert_eq!(
            public_entity_id("username", "Rx"),
            public_entity_id("username", "rx")
        );
        assert_ne!(
            public_entity_id("username", "rx"),
            public_entity_id("domain", "rx")
        );
    }
}
