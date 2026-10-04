use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum TechCategory {
    WebServer,
    ReverseProxy,
    Framework,
    Cms,
    Runtime,
    Language,
    Application,
    ApiFramework,
    ManagementInterface,
}

impl TechCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WebServer => "web_server",
            Self::ReverseProxy => "reverse_proxy",
            Self::Framework => "framework",
            Self::Cms => "cms",
            Self::Runtime => "runtime",
            Self::Language => "language",
            Self::Application => "application",
            Self::ApiFramework => "api_framework",
            Self::ManagementInterface => "management_interface",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebTechnology {
    pub name: String,
    pub category: TechCategory,
    pub confidence: u8,
    pub signals: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SignalStrength {
    Strong,
    Weak,
}

struct TechRule {
    name: &'static str,
    category: TechCategory,
    markers: &'static [&'static str],
    strong: bool,
}

const RULES: &[TechRule] = &[
    TechRule {
        name: "nginx",
        category: TechCategory::WebServer,
        markers: &["server: nginx", "nginx/"],
        strong: true,
    },
    TechRule {
        name: "Apache",
        category: TechCategory::WebServer,
        markers: &["server: apache", "apache/"],
        strong: true,
    },
    TechRule {
        name: "Caddy",
        category: TechCategory::WebServer,
        markers: &["server: caddy", "caddy/"],
        strong: true,
    },
    TechRule {
        name: "IIS",
        category: TechCategory::WebServer,
        markers: &["server: microsoft-iis"],
        strong: true,
    },
    TechRule {
        name: "lighttpd",
        category: TechCategory::WebServer,
        markers: &["server: lighttpd"],
        strong: true,
    },
    TechRule {
        name: "Envoy",
        category: TechCategory::ReverseProxy,
        markers: &["server: envoy", "x-envoy"],
        strong: true,
    },
    TechRule {
        name: "HAProxy",
        category: TechCategory::ReverseProxy,
        markers: &["server: haproxy"],
        strong: true,
    },
    TechRule {
        name: "Traefik",
        category: TechCategory::ReverseProxy,
        markers: &["server: traefik"],
        strong: true,
    },
    TechRule {
        name: "Varnish",
        category: TechCategory::ReverseProxy,
        markers: &["via: varnish", "x-varnish", "server: varnish"],
        strong: true,
    },
    TechRule {
        name: "Squid",
        category: TechCategory::ReverseProxy,
        markers: &["server: squid", "via: squid", "x-squid"],
        strong: true,
    },
    TechRule {
        name: "Cloudflare",
        category: TechCategory::ReverseProxy,
        markers: &["server: cloudflare", "cf-ray", "__cfduid"],
        strong: false,
    },
    TechRule {
        name: "WordPress",
        category: TechCategory::Cms,
        markers: &["wp-content/", "wp-json/", "wordpress"],
        strong: true,
    },
    TechRule {
        name: "Drupal",
        category: TechCategory::Cms,
        markers: &["drupal", "sites/default/files"],
        strong: true,
    },
    TechRule {
        name: "Joomla",
        category: TechCategory::Cms,
        markers: &["joomla", "/media/jui/"],
        strong: true,
    },
    TechRule {
        name: "Ghost",
        category: TechCategory::Cms,
        markers: &["ghost", "x-ghost"],
        strong: false,
    },
    TechRule {
        name: "Django",
        category: TechCategory::Framework,
        markers: &["csrftoken", "django"],
        strong: false,
    },
    TechRule {
        name: "Rails",
        category: TechCategory::Framework,
        markers: &["_rails", "x-rails", "rails"],
        strong: false,
    },
    TechRule {
        name: "Express",
        category: TechCategory::Framework,
        markers: &["x-powered-by: express"],
        strong: true,
    },
    TechRule {
        name: "Next.js",
        category: TechCategory::Framework,
        markers: &["__next", "_next/static", "next.js"],
        strong: true,
    },
    TechRule {
        name: "Nuxt",
        category: TechCategory::Framework,
        markers: &["__nuxt", "_nuxt/", "nuxt"],
        strong: true,
    },
    TechRule {
        name: "Node.js",
        category: TechCategory::Runtime,
        markers: &["x-powered-by: express", "node.js"],
        strong: false,
    },
    TechRule {
        name: "PHP",
        category: TechCategory::Language,
        markers: &["x-powered-by: php", "phpsessid"],
        strong: true,
    },
    TechRule {
        name: "Python",
        category: TechCategory::Language,
        markers: &["wsgi", "gunicorn", "uvicorn", "werkzeug"],
        strong: false,
    },
    TechRule {
        name: "Grafana",
        category: TechCategory::Application,
        markers: &["grafana", "__grafana"],
        strong: true,
    },
    TechRule {
        name: "Kibana",
        category: TechCategory::Application,
        markers: &["kibana", "kbn-"],
        strong: true,
    },
    TechRule {
        name: "Prometheus",
        category: TechCategory::Application,
        markers: &["prometheus"],
        strong: true,
    },
    TechRule {
        name: "Jenkins",
        category: TechCategory::ManagementInterface,
        markers: &["jenkins", "x-jenkins"],
        strong: true,
    },
    TechRule {
        name: "GitLab",
        category: TechCategory::ManagementInterface,
        markers: &["gitlab"],
        strong: true,
    },
    TechRule {
        name: "MinIO",
        category: TechCategory::Application,
        markers: &["minio", "x-minio"],
        strong: true,
    },
    TechRule {
        name: "OpenAPI",
        category: TechCategory::ApiFramework,
        markers: &["openapi", "swagger", "/openapi.json"],
        strong: false,
    },
    TechRule {
        name: "GraphQL",
        category: TechCategory::ApiFramework,
        markers: &["graphql", "/graphql"],
        strong: false,
    },
];

pub const MAX_TECHNOLOGIES: usize = 8;
pub const WEAK_CONFIDENCE_CAP: u8 = 55;
pub const STRONG_CONFIDENCE: u8 = 85;

pub fn identify(headers: &BTreeMap<String, String>, body_excerpt: &str) -> Vec<WebTechnology> {
    let mut corpus = String::with_capacity(2048);
    for (name, value) in headers {
        corpus.push_str(&name.to_ascii_lowercase());
        corpus.push_str(": ");
        corpus.push_str(&value.to_ascii_lowercase());
        corpus.push('\n');
    }
    corpus.push_str(&body_excerpt.to_ascii_lowercase());

    let mut out = Vec::new();
    for rule in RULES {
        let mut hits = Vec::new();
        for marker in rule.markers {
            if corpus.contains(marker) {
                hits.push((*marker).to_owned());
            }
        }
        if hits.is_empty() {
            continue;
        }
        let strength = if rule.strong {
            SignalStrength::Strong
        } else {
            SignalStrength::Weak
        };
        let confidence = match strength {
            SignalStrength::Strong => STRONG_CONFIDENCE.min(85),
            SignalStrength::Weak => WEAK_CONFIDENCE_CAP.min(55),
        };
        out.push(WebTechnology {
            name: rule.name.to_owned(),
            category: rule.category,
            confidence,
            signals: hits,
        });
        if out.len() >= MAX_TECHNOLOGIES {
            break;
        }
    }
    out.sort_by(|a, b| {
        b.confidence
            .cmp(&a.confidence)
            .then_with(|| a.name.cmp(&b.name))
    });
    out.truncate(MAX_TECHNOLOGIES);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn strong_server_header_identifies() {
        let techs = identify(&headers(&[("Server", "nginx/1.24.0")]), "");
        assert!(
            techs
                .iter()
                .any(|t| t.name == "nginx" && t.confidence >= 80)
        );
    }

    #[test]
    fn weak_signals_capped() {
        let techs = identify(&headers(&[("Set-Cookie", "csrftoken=abc")]), "");
        let django = techs.iter().find(|t| t.name == "Django").unwrap();
        assert!(django.confidence <= WEAK_CONFIDENCE_CAP);
    }

    #[test]
    fn weak_signal_never_reaches_strong_confidence() {
        let techs = identify(&headers(&[("X-Foo", "rails hint rails")]), "");
        for tech in &techs {
            if tech.name == "Rails" {
                assert!(tech.confidence <= 55);
            }
        }
    }

    #[test]
    fn empty_input_identifies_nothing() {
        assert!(identify(&BTreeMap::new(), "").is_empty());
    }

    #[test]
    fn output_bounded_and_deterministic() {
        let h = headers(&[
            ("Server", "nginx"),
            ("X-Powered-By", "Express"),
            ("Set-Cookie", "phpsessid=1"),
        ]);
        let first = identify(&h, "wp-content/ graphql");
        assert!(first.len() <= MAX_TECHNOLOGIES);
        assert_eq!(first, identify(&h, "wp-content/ graphql"));
    }

    #[test]
    fn categories_are_explicit() {
        let techs = identify(&headers(&[("Server", "nginx/1.0")]), "");
        assert_eq!(
            techs.iter().find(|t| t.name == "nginx").unwrap().category,
            TechCategory::WebServer
        );
    }
}
