window.DARKRX = {
  passphrase: "darkrx",
  identity: {
    kicker: "DARKRX // PUBLIC IDENTITY",
    name: "DARKRX",
    roles: ["PURPLE TEAMER", "SECURITY RESEARCHER", "ADVERSARY SIMULATION"],
    manifesto: [
      "Attack systems.",
      "Study the telemetry.",
      "Build the detection.",
      "Break it again.",
    ],
  },
  about: {
    pill: "About Me",
    title: ["Building", "Detection"],
    subtitle: "Attack systems. Study the telemetry. Build the detection. Break it again.",
    name: "DARKRX",
    titleLine: "Purple Teamer & Security Researcher",
    p1: "Operator identity first. DarkRX is a cyber research lab and adversary-simulation practice: break the path, read the logs, write the detection, then run it again until the gap closes.",
    p2: "The work is the evidence. No résumé dump on the front door — education, youth work, and earlier digital projects sit here as supporting signal, not the headline.",
    tags: ["Purple Team", "Detection Eng", "Adversary Sim", "SIEM", "Wazuh"],
    stats: [
      { value: "2019+", label: "Digital Work", icon: "code" },
      { value: "7y", label: "Building", icon: "briefcase" },
      { value: "Lab", label: "Research", icon: "award" },
      { value: "Comm", label: "Leadership", icon: "users" },
    ],
  },
  education: [
    {
      degree: "Technical Programme",
      institution: "Lars Kaggskolan",
      period: "Programme",
      score: "Technical foundation used as supporting evidence — not the public headline.",
    },
  ],
  certs: [
    { name: "Self-directed cybersecurity fundamentals", issuer: "Independent / lab work" },
    { name: "Detection engineering practice", issuer: "Wazuh · Sysmon · Sigma" },
    { name: "Adversary simulation drills", issuer: "ATT&CK-mapped lab ops" },
    { name: "Web & API authorization testing", issuer: "Research notes" },
  ],
  pursuing: ["eJPT-style offensive validation", "Sigma correlation depth", "AD detection coverage"],
  experience: [
    {
      role: "Adversary simulation & detection validation",
      org: "DarkRX Lab",
      period: "Ongoing",
      location: "Private lab",
      description:
        "Credential access, lateral movement, and web-attack validation against SIEM coverage. Findings stay in the private console; public writeups stay sanitized.",
    },
    {
      role: "Independent digital builder",
      org: "Websites & small games",
      period: "2019 — present",
      location: "Self-directed",
      description:
        "Shipped sites and small games since 2019. That build loop — including horror-game experiments — still shapes the DarkRX aesthetic without turning this into a game portfolio.",
    },
    {
      role: "Youth work & community engagement",
      org: "Community",
      period: "Supporting",
      location: "IRL / content",
      description:
        "Youth work, content creation, and community-building. Useful operator traits. Kept below the cyber identity so they do not visually overpower the lab.",
    },
  ],
  leadership: [
    {
      org: "Community & content",
      roles: [
        { title: "Youth work", period: "Supporting" },
        { title: "Content / engagement", period: "Ongoing" },
      ],
    },
  ],
  projects: [
    {
      title: "Wazuh detection validation",
      blurb: "Replay credential-access and lateral-movement paths. Measure what alerts, what does not, patch the rule, retest.",
      tags: ["Wazuh", "Sysmon", "T1003"],
    },
    {
      title: "AD lateral movement gaps",
      blurb: "Map telemetry across Event Logs and Sysmon. Hunt missing correlation between host A and host B.",
      tags: ["Active Directory", "Sigma"],
    },
    {
      title: "API authorization testing",
      blurb: "Broken-object and privilege checks on lab APIs. Public notes stay high-level; full traces live behind auth.",
      tags: ["API", "AuthZ"],
    },
    {
      title: "Web attack validation",
      blurb: "Controlled web-attack paths used to prove detection, not to collect trophies.",
      tags: ["Web", "Purple"],
    },
  ],
  skills: [
    {
      name: "Offensive / sim",
      items: [
        { n: "Adversary simulation", p: 78 },
        { n: "Web / API testing", p: 72 },
        { n: "Credential access paths", p: 70 },
      ],
    },
    {
      name: "Defensive / detect",
      items: [
        { n: "Wazuh / SIEM", p: 80 },
        { n: "Sysmon + Windows logs", p: 76 },
        { n: "Sigma / correlation", p: 68 },
      ],
    },
    {
      name: "Build",
      items: [
        { n: "Websites & tooling", p: 74 },
        { n: "Python / scripting", p: 70 },
        { n: "Games / narrative systems", p: 55 },
      ],
    },
  ],
  posts: [
    {
      slug: "sanitized-lateral-movement",
      date: "2026-08-12",
      title: "What public writeups omit from AD lateral movement",
      excerpt: "High-level detection ideas without payloads. Full operator notes stay in the vault.",
    },
    {
      slug: "wazuh-validation-loop",
      date: "2026-07-02",
      title: "The validation loop: attack, telemetry, detection, retest",
      excerpt: "Purple-team rhythm in four verbs. The private case studies are where the gaps get named.",
    },
    {
      slug: "no-face-no-cv-dump",
      date: "2026-06-18",
      title: "Operator portfolios without the selfie résumé",
      excerpt: "Identity as work product. Supporting life goes in /about, not the hero.",
    },
  ],
  contact: {
    email: "ops@darkrx.local",
    note: "Public inbox for research contact. Engagement artifacts stay in the private console.",
  },
  console: {
    counts: [
      ["RESEARCH", 12],
      ["BLOG", 18],
      ["CASE STUDIES", 9],
      ["DETECTIONS", 31],
      ["ENGAGEMENTS", 6],
    ],
    research: [
      "AD lateral movement detection gaps",
      "Wazuh detection validation",
      "API authorization testing",
    ],
    ops: [
      "OP-009 credential access",
      "OP-008 phishing simulation",
      "OP-007 web attack validation",
    ],
  },
  caseStudy: {
    id: "CS-031",
    title: "Credential access coverage — T1003",
    rows: [
      ["TARGET", "Windows / Active Directory"],
      ["OBJECTIVE", "Validate detection coverage for T1003"],
      ["ATTACK", "Credential access simulation"],
      ["TELEMETRY", "Sysmon · Windows Event Logs · SIEM"],
      ["DETECTION", "Sigma rule · Correlation · Alert enrichment"],
      ["RESULT", "PARTIAL"],
      ["GAP", "Missing correlation between LSASS access and subsequent DC auth from a new host"],
      ["REMEDIATION", "Rule modified — join Sysmon 10 with 4624/4769 in a short window"],
      ["RETEST", "PASS"],
    ],
  },
};
