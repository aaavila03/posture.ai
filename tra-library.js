// Reference data for threat risk assessments: impact rows, asset questions, threats and the
// security control library. tra.js holds the logic that uses it.
//
// Control IDs are numbered by position and saved in assessments, so they must keep their
// meaning: add new controls at the end of a section, and don't reorder or remove them.
// Bump LIBRARY_VERSION whenever this file changes.
//
// Each control's rules say when it applies, as "question:tier":
//   the question is "general" (always asked) or a key from TRIGGERS;
//   the tier is the lowest overall impact it applies to: L = any, M = Moderate and up, H = High and up.
// A control is selected when its asset type matches and any one of its rules fires.

export const LIBRARY_VERSION = "2026.1";

// ---------- impact ----------
export const IMPACT_LEVELS = [
  ["A", "Very High", 10], ["B", "High", 8], ["C", "Moderate", 5], ["D", "Low", 2], ["E", "Very Low", 1],
];

const MONEY = ["Over $30M", "$5M to $30M", "$1M to $5M", "$100K to $1M", "Under $100K"];
const PERCENT = ["More than 20%", "11% to 20%", "6% to 10%", "1% to 5%", "Under 1%"];
const LEGAL_MONEY = ["Over $1B", "$100M to $1B", "$10M to $100M", "$1M to $10M", "Under $1M"];
const extent = (noun) => [`Severe ${noun}`, `Serious ${noun}`, `Significant ${noun}`, `Moderate ${noun}`, `Minor ${noun}`];

// levels run from A (Very High) to E (Very Low).
export const IMPACT_ROWS = [
  { id: "B1", group: "Business", label: "Lost revenue or contracts", measure: "Drop in annual revenue", levels: PERCENT },
  { id: "B2", group: "Business", label: "Loss of physical or financial assets", measure: "Financial impact", levels: MONEY },
  { id: "B3", group: "Business", label: "Unplanned costs, such as recovery or compensation", measure: "Financial impact", levels: MONEY },
  { id: "B4", group: "Business", label: "Fall in company value or share price", measure: "Loss of value", levels: ["More than 25%", "11% to 25%", "6% to 10%", "1% to 5%", "Under 1%"] },
  { id: "B5", group: "Business", label: "Weakened management control or decision-making", measure: "Loss of control", levels: extent("loss of control") },
  { id: "B6", group: "Business", label: "Weakened competitive position", measure: "Targets missed", levels: PERCENT },
  { id: "B7", group: "Business", label: "New initiatives delayed", measure: "Length of delay", levels: ["Initiative cancelled", "Delayed by years", "Delayed by months", "Delayed by weeks", "Delayed by days"] },
  { id: "B8", group: "Business", label: "Lower staff morale or productivity", measure: "Effect on staff", levels: extent("effect on staff") },
  { id: "B9", group: "Business", label: "Harm to people", measure: "Severity", levels: ["One or more fatalities", "Life-threatening injury or permanent disability", "Serious injury needing professional care", "Injury needing treatment beyond first aid", "Minor injury needing first aid"] },
  { id: "L1", group: "Legal", label: "Fines and legal liability", measure: "Financial impact", levels: LEGAL_MONEY },
  { id: "L2", group: "Legal", label: "Breach of regulatory or operating requirements", measure: "Regulator action", levels: ["Licence lost everywhere", "Licence lost in a key region", "A site closed for a long period", "Moderate sanctions", "Minor sanctions"] },
  { id: "L3", group: "Legal", label: "Privacy breach", measure: "Financial impact", levels: LEGAL_MONEY },
  { id: "R1", group: "Reputation", label: "Delayed service to customers", measure: "Length of delay", levels: ["6 months or more", "About 3 months", "About 1 month", "About 1 week", "About 1 day"] },
  { id: "R2", group: "Reputation", label: "Customers lost", measure: "Share of customers", levels: ["More than 25%", "11% to 25%", "6% to 10%", "1% to 5%", "Under 1%"] },
  { id: "R3", group: "Reputation", label: "Loss of confidence among investors, regulators or partners", measure: "Loss of confidence", levels: extent("loss of confidence") },
  { id: "R4", group: "Reputation", label: "Negative publicity", measure: "Reach", levels: ["Worldwide", "Across a continent", "National", "Local", "Very limited"] },
];

// ---------- likelihood, treatment ----------
export const LIKELIHOODS = [
  ["Probable", 10, "96–100%"], ["Likely", 8, "80–95%"], ["Possible", 5, "21–79%"], ["Unlikely", 2, "5–20%"], ["Remote", 1, "0–4%"],
];
export const TREATMENTS = ["Accept", "Reduce", "Avoid", "Share"];
export const COMPLIANCE = ["Yes", "No", "Partially", "Not applicable"];

// ---------- asset profile ----------
export const ASSET_TYPES = [
  ["app", "Application software"], ["os", "Operating system"], ["net", "Hardware and network"], ["ot", "Operational technology (OT)"],
];
// Yes/No questions that bring in extra controls. `when` is the answer that triggers them.
export const TRIGGERS = [
  { key: "virtual", label: "Runs in a virtual environment or as a virtual appliance?", when: "Yes" },
  { key: "embedded", label: "Includes embedded software in a device?", when: "Yes" },
  { key: "external", label: "Connected to external networks?", when: "Yes" },
  { key: "cloud", label: "Runs in, or stores data in, the cloud?", when: "Yes" },
  { key: "web", label: "Has web interfaces, such as portals or APIs?", when: "Yes" },
  { key: "internet", label: "Has an interface exposed to the internet?", when: "Yes" },
  { key: "centralAuth", label: "Is sign-in managed by a central service (SSO)?", when: "No" },
  { key: "thirdParty", label: "Will third parties develop, run or process data for it?", when: "Yes" },
  { key: "otEol", label: "Is the OT system past its end of life?", when: "Yes", onlyFor: "ot" },
];
export const AUTH_METHODS = [
  ["passwords", "Passwords"], ["otp", "One-time passwords"], ["pins", "PINs"], ["smartcards", "Smartcards"], ["pki", "PKI"],
  ["certs", "Digital certificates"], ["keys", "Cryptographic keys"], ["noAuth", "No sign-in mechanism"],
];

// ---------- threats ----------
export const THREAT_CATEGORIES = ["External attacks", "Insider misuse", "Theft and loss", "System failure", "Service disruption", "Human error", "Effects of change"];

const threat = (id, category, name, description) => ({ id, category: THREAT_CATEGORIES[category], name, description });
export const THREATS = [
  threat("dos", 0, "Denial of service", "Flooding systems or networks so legitimate users can't reach them."),
  threat("intrusion", 0, "Network or system intrusion", "An outsider breaking into systems or networks."),
  threat("recon", 0, "Reconnaissance and scanning", "Probing systems to find weaknesses to attack."),
  threat("credattack", 0, "Password and credential attacks", "Guessing, cracking or replaying stolen credentials."),
  threat("cryptoattack", 0, "Attacks on encryption", "Breaking or bypassing keys and weak encryption."),
  threat("webtamper", 0, "Website tampering", "Changing the content of a website without permission."),
  threat("sitespoof", 0, "Fake websites", "Imitating a genuine site to trick users into visiting it."),
  threat("impersonate", 0, "Identity impersonation", "Using someone's valid identity to get access."),
  threat("trafficmod", 0, "Traffic manipulation", "Redirecting or altering network traffic in transit."),
  threat("intercept", 0, "Interception of data in transit", "Listening in on information as it crosses a network."),
  threat("malware", 0, "Malware", "Viruses, worms, spyware and similar malicious software."),
  threat("ransomware", 0, "Ransomware", "Encrypting or stealing data to demand payment."),
  threat("phishing", 0, "Phishing and social engineering", "Tricking people into giving up access or information."),
  threat("supplychain", 0, "Supply chain compromise", "An attack that arrives through a supplier, update or dependency."),
  threat("insideraccess", 1, "Unauthorized internal access", "Staff reaching systems or data they aren't allowed to use."),
  threat("privabuse", 1, "Abuse of privileges", "Raising or misusing permissions without approval."),
  threat("rogueswchange", 1, "Unauthorized software changes", "Changing or adding software to alter how a system behaves."),
  threat("datatamper", 1, "Tampering with data", "Changing transactions, files or databases without approval."),
  threat("sabotage", 1, "Deliberate disruption", "Using legitimate access to degrade a system on purpose."),
  threat("fraud", 1, "Fraud", "Using legitimate systems to defraud the organization."),
  threat("shadowit", 1, "Unapproved software", "Installing software from an untrusted or unapproved source."),
  threat("credshare", 1, "Sharing of credentials", "Passing sign-in details to others."),
  threat("datadisclose", 1, "Disclosure of business data", "Leaking confidential information, on purpose or otherwise."),
  threat("datatheft", 2, "Theft of business data", "Stealing customer lists, designs or intellectual property."),
  threat("pii", 2, "Theft of personal data", "Stealing information that identifies people."),
  threat("devicetheft", 2, "Theft or loss of equipment", "Laptops, phones, removable media or other devices going missing."),
  threat("credtheft", 2, "Theft of credentials", "Stealing passwords, tokens, PINs or keys."),
  threat("softwaretheft", 2, "Theft or misuse of software", "Copying software or using it without a licence."),
  threat("appfail", 3, "Application failure", "A business application failing or behaving incorrectly."),
  threat("sysfail", 3, "System software failure", "An operating system or utility failing."),
  threat("hwfail", 3, "Equipment failure", "Computing or network hardware failing."),
  threat("sitefail", 4, "Loss of facilities", "Damage to or loss of a data center, control room or site."),
  threat("commsfail", 4, "Loss of communications", "Internet, network or wireless links going down."),
  threat("powerfail", 4, "Loss of power", "Mains or backup power failing."),
  threat("envfail", 4, "Loss of cooling or support equipment", "Failure of the equipment systems depend on."),
  threat("disaster", 4, "Natural disaster", "Storm, flood, fire, earthquake or extreme weather."),
  threat("overload", 4, "System overload", "Too much activity slowing or stopping a system."),
  threat("usererror", 5, "User mistakes", "Errors by people using a system, such as wrong data or recipients."),
  threat("adminerror", 5, "Administrator mistakes", "Errors by the people who run systems and networks."),
  threat("processchange", 6, "New or changed business process", "Harm caused by introducing or changing a process."),
  threat("softwarechange", 6, "Software change", "Unexpected results from new or updated software."),
  threat("datachange", 6, "Change to business data", "Harm caused by changes to important information."),
  threat("hwchange", 6, "Equipment change", "Unexpected results from new or changed hardware."),
  threat("orgchange", 6, "Organizational change", "Harm caused by reorganizing, mergers or outsourcing."),
];

// ---------- controls ----------
export const CONTROL_SECTIONS = {
  AC: "Access control", DP: "Data protection and classification", CM: "Configuration management", NS: "Network security",
  SD: "Secure development", VM: "Threat and vulnerability management", VC: "Vendor and cloud management", PE: "Physical and environmental security",
  OA: "OT asset and configuration management", OD: "OT data protection", OI: "OT identity and access", ON: "OT infrastructure security",
  OS: "OT security operations", OV: "OT vulnerability management",
};

// One line per control: section, requirement, the gap if it's missing, NIST SP 800-53 reference,
// rules, threats. An optional last argument limits the asset types (default: application, OS, network).
const DEFINED = [
  // Access control
  ["AC", "Connect the system to the organization's single sign-on service.", "The system isn't connected to single sign-on, so accounts are managed separately and are harder to control.", "AC-2", "general:M", "credattack impersonate insideraccess"],
  ["AC", "Require multi-factor authentication for all users.", "Multi-factor authentication isn't required, so one stolen password is enough to get in.", "IA-2", "general:M internet:L external:L", "credattack credtheft impersonate phishing"],
  ["AC", "Require multi-factor authentication for all privileged accounts.", "Privileged accounts can sign in without a second factor.", "IA-2", "general:L", "credattack credtheft privabuse intrusion"],
  ["AC", "Grant access through defined roles rather than to individuals.", "Access isn't role-based, so permissions are inconsistent and hard to review.", "AC-3", "general:L", "insideraccess privabuse"],
  ["AC", "Give users only the access their job needs.", "Users have more access than they need, widening the damage from misuse or compromise.", "AC-6", "general:L", "insideraccess privabuse datadisclose"],
  ["AC", "Separate duties so no one person can complete a sensitive action alone.", "Sensitive actions can be completed by one person without a check.", "AC-5", "general:M", "fraud datatamper privabuse"],
  ["AC", "Have a manager or owner approve new access before it's granted.", "Access can be granted without documented approval.", "AC-2", "general:L", "insideraccess privabuse"],
  ["AC", "Remove access promptly when someone leaves or changes role.", "Access isn't removed promptly, leaving accounts that former staff or attackers could use.", "AC-2", "general:L", "insideraccess impersonate credshare"],
  ["AC", "Review user access at least every quarter for privileged users and yearly for others.", "Access isn't reviewed regularly, so excess permissions go unnoticed.", "AC-2", "general:L", "insideraccess privabuse"],
  ["AC", "Keep an up-to-date inventory of accounts, including service accounts.", "There's no complete list of accounts, so unused or rogue ones can persist.", "AC-2", "general:M", "insideraccess impersonate"],
  ["AC", "Disable accounts after a set period of inactivity.", "Inactive accounts stay enabled and can be taken over unnoticed.", "AC-2", "general:M", "impersonate credattack"],
  ["AC", "Require unique IDs and prohibit shared user accounts.", "Shared accounts make it impossible to tell who did what.", "IA-2", "general:L", "credshare insideraccess fraud"],
  ["AC", "Keep administrator accounts separate from everyday accounts.", "Administrators use the same account for daily work, exposing privileged access to phishing and malware.", "AC-6", "general:M", "phishing malware privabuse"],
  ["AC", "Use a privileged access tool to control and record administrator sessions.", "Privileged sessions aren't controlled or recorded.", "AC-6", "general:H", "privabuse insideraccess adminerror"],
  ["AC", "Grant elevated access only for a limited time when it's needed.", "Elevated access is standing, giving attackers more opportunity to abuse it.", "AC-6", "general:H", "privabuse intrusion"],
  ["AC", "Require re-authentication before raising privileges.", "Privileges can be raised without proving identity again.", "AC-6", "general:M", "privabuse impersonate"],
  ["AC", "Record every change to roles and permissions.", "Changes to roles and permissions aren't recorded, so unauthorized changes can go unseen.", "AC-6", "general:L", "privabuse rogueswchange"],
  ["AC", "Alert on unexpected privilege changes and unusual administrator activity.", "Unexpected privilege changes don't raise an alert.", "AC-6", "general:M", "privabuse intrusion insideraccess"],
  ["AC", "Limit failed sign-in attempts and lock or slow further tries.", "Unlimited sign-in attempts allow password guessing.", "AC-7", "general:L", "credattack"],
  ["AC", "End or lock idle sessions automatically.", "Idle sessions stay open and can be used by someone else.", "AC-11", "general:L", "insideraccess impersonate"],
  ["AC", "Show a notice of acceptable use at sign-in where required.", "Users aren't told the terms of use when they sign in.", "AC-8", "general:M", "insideraccess"],
  ["AC", "Limit how many sessions a user can have open at once where it matters.", "Unlimited simultaneous sessions make stolen credentials harder to spot.", "AC-10", "general:H", "impersonate credtheft"],
  ["AC", "Restrict administrative access to approved networks or managed devices.", "Administrative interfaces can be reached from unapproved places.", "AC-17", "general:M external:L", "intrusion privabuse"],
  ["AC", "Secure remote access with encryption and multi-factor authentication.", "Remote access isn't fully protected by encryption and a second factor.", "AC-17", "external:L", "intrusion credattack intercept"],
  ["AC", "Check device health before allowing remote or privileged access.", "Unmanaged or unhealthy devices can connect.", "AC-19", "external:M general:H", "malware intrusion"],
  ["AC", "Log sign-ins, sign-in failures and administrator actions, and protect those logs.", "Security events aren't logged or the logs aren't protected, limiting investigations.", "AU-2", "general:L", "intrusion insideraccess fraud"],
  ["AC", "Send security logs to a central monitoring system.", "Logs aren't centrally monitored, so attacks can go unnoticed.", "AU-6", "general:M", "intrusion malware insideraccess"],
  ["AC", "Keep logs for a defined period that meets legal and investigation needs.", "Logs aren't kept long enough to investigate incidents.", "AU-11", "general:M", "intrusion fraud"],
  ["AC", "Use a separate strong sign-in for local accounts where SSO isn't available.", "Accounts outside central sign-in have no compensating protection.", "IA-5", "centralAuth:L", "credattack impersonate"],
  ["AC", "Review local accounts more often when central sign-in isn't used.", "Local accounts aren't reviewed, so leavers may keep access.", "AC-2", "centralAuth:L", "insideraccess credshare"],
  ["AC", "Provide a controlled process for joining and leaving when central sign-in isn't used.", "Joiners and leavers aren't managed consistently in the local directory.", "AC-2", "centralAuth:M", "insideraccess"],
  ["AC", "Set a password policy for length, complexity and known-breached passwords.", "Weak or breached passwords can be used.", "IA-5", "passwords:L", "credattack"],
  ["AC", "Store passwords only as salted, strong one-way hashes.", "Passwords aren't stored safely and could be exposed in a breach.", "IA-5", "passwords:L", "credattack credtheft"],
  ["AC", "Change default passwords before a system goes live.", "Default passwords may remain in use.", "IA-5", "passwords:L", "credattack intrusion"],
  ["AC", "Use an approved vault for service account and shared secrets.", "Secrets are stored outside an approved vault.", "IA-5", "passwords:M keys:L", "credtheft insideraccess"],
  ["AC", "Keep one-time password seeds protected and limit how long each code works.", "One-time password seeds or lifetimes aren't controlled.", "IA-5", "otp:L", "credtheft impersonate"],
  ["AC", "Protect against one-time password replay and prompt-fatigue attacks.", "One-time password checks can be replayed or approved by mistake.", "IA-2", "otp:M", "phishing impersonate"],
  ["AC", "Require PINs of a suitable length and block simple sequences.", "Simple PINs can be guessed.", "IA-5", "pins:L", "credattack"],
  ["AC", "Lock the credential after repeated wrong PIN entries.", "Repeated wrong PINs don't lock the credential.", "AC-7", "pins:L", "credattack"],
  ["AC", "Issue smartcards through a controlled process and revoke them as soon as they're lost.", "Smartcards aren't issued or revoked in a controlled way.", "IA-5", "smartcards:L", "devicetheft impersonate"],
  ["AC", "Run PKI under a documented certificate policy with protected root keys.", "PKI isn't governed by a policy, or its root keys aren't protected.", "SC-17", "pki:L", "cryptoattack impersonate"],
  ["AC", "Check that certificates haven't been revoked when they're used.", "Revoked certificates may still be accepted.", "IA-5", "pki:M certs:L", "impersonate intercept"],
  ["AC", "Track certificates and renew them before they expire.", "Certificates aren't tracked, so they can expire and cause outages.", "SC-17", "certs:L", "commsfail adminerror"],
  ["AC", "Require an approved sign-in or document why none is needed and limit network access.", "The system has no sign-in, so anyone who can reach it can use it.", "IA-2", "noAuth:L", "insideraccess intrusion"],
  // Data protection and classification
  ["DP", "Identify and classify the data the system holds.", "Data hasn't been classified, so its protection may not match its sensitivity.", "RA-2", "general:L", "datadisclose datatheft pii"],
  ["DP", "Name an owner for the system's data.", "No one owns the data, so decisions about access and retention aren't made.", "PM-2", "general:L", "datadisclose usererror"],
  ["DP", "Label or tag sensitive data so that handling rules can be applied.", "Sensitive data isn't labeled, so handling rules can't be applied.", "AC-16", "general:M", "datadisclose usererror"],
  ["DP", "Encrypt sensitive data at rest using current, approved algorithms.", "Sensitive data at rest isn't encrypted to current standards.", "SC-28", "general:L", "datatheft pii devicetheft"],
  ["DP", "Encrypt data in transit using current TLS or an equivalent.", "Data in transit isn't fully encrypted and could be intercepted.", "SC-8", "general:L", "intercept trafficmod datatheft"],
  ["DP", "Protect encryption keys and rotate them on a schedule.", "Keys aren't managed or rotated, weakening the encryption they protect.", "SC-12", "general:M keys:L", "cryptoattack credtheft"],
  ["DP", "Store keys separately from the data they protect.", "Keys are stored alongside the data they protect.", "SC-12", "keys:L", "cryptoattack datatheft"],
  ["DP", "Use a hardware security module or managed key service for high-value keys.", "High-value keys aren't held in dedicated secure hardware or a managed service.", "SC-12", "keys:M", "cryptoattack credtheft"],
  ["DP", "Remove or mask sensitive data in non-production environments.", "Real sensitive data is used in test or development environments.", "SA-3", "general:M", "datadisclose pii"],
  ["DP", "Hide sensitive fields from users who don't need to see them.", "Sensitive fields are visible to users who don't need them.", "AC-3", "general:M", "datadisclose pii insideraccess"],
  ["DP", "Use data loss prevention to detect sensitive data leaving the organization.", "Sensitive data can leave the organization without being detected.", "SC-7", "general:M", "datadisclose datatheft"],
  ["DP", "Block or control the use of removable media with sensitive data.", "Sensitive data can be copied to uncontrolled removable media.", "MP-7", "general:M", "datatheft devicetheft malware"],
  ["DP", "Encrypt laptops and mobile devices that can hold sensitive data.", "Devices holding sensitive data may be unencrypted if lost or stolen.", "SC-28", "general:M", "devicetheft pii"],
  ["DP", "Back up important data and systems on a defined schedule.", "Backups aren't scheduled, so data could be lost permanently.", "CP-9", "general:L", "ransomware appfail usererror"],
  ["DP", "Keep at least one backup copy offline or immutable.", "Backups could be encrypted or deleted in the same attack.", "CP-9", "general:M", "ransomware sabotage"],
  ["DP", "Test restoring from backup at least once a year.", "Backups haven't been tested and may not work when needed.", "CP-9", "general:L", "ransomware appfail hwfail"],
  ["DP", "Encrypt backups and restrict who can reach them.", "Backups aren't encrypted or access to them isn't limited.", "CP-9", "general:M", "datatheft insideraccess"],
  ["DP", "Keep a recovery plan with agreed recovery time and data-loss targets.", "No recovery plan or targets exist, so recovery could take too long.", "CP-2", "general:L", "disaster sitefail ransomware"],
  ["DP", "Test the recovery plan on a regular schedule.", "The recovery plan hasn't been tested.", "CP-4", "general:M", "disaster sitefail commsfail"],
  ["DP", "Provide redundancy for systems that have strict availability needs.", "A single failure can take the system offline.", "CP-7", "general:H", "hwfail commsfail powerfail overload"],
  ["DP", "Monitor capacity and plan for growth.", "Capacity isn't monitored, so the system could run out of resources.", "AU-5", "general:M", "overload dos"],
  ["DP", "Keep and delete data according to a retention schedule.", "Data is kept without a retention schedule, adding risk and legal exposure.", "SI-12", "general:L", "datadisclose pii"],
  ["DP", "Securely wipe or destroy media when it's retired.", "Retired media may still contain readable data.", "MP-6", "general:L", "datatheft devicetheft"],
  ["DP", "Record what personal data is held, why, and on what legal basis.", "There's no record of the personal data held and why.", "PT-3", "general:L", "pii datadisclose"],
  ["DP", "Assess privacy impact before processing personal data in a new way.", "New uses of personal data aren't assessed for privacy impact.", "RA-8", "general:M", "pii datadisclose processchange"],
  ["DP", "Check data integrity for critical transactions and files.", "Critical data can be changed without being detected.", "SI-7", "general:M", "datatamper fraud"],
  ["DP", "Validate data at system boundaries to prevent errors entering.", "Bad data can enter the system unchecked.", "SI-10", "general:L", "usererror datatamper"],
  ["DP", "Keep a tamper-evident record of important business transactions.", "Important transactions can't be traced reliably.", "AU-10", "general:H", "fraud datatamper"],
  ["DP", "Have an agreed process for responding to a data breach, including notification.", "There's no agreed breach response or notification process.", "IR-8", "general:L", "pii datatheft datadisclose"],
  // Configuration management
  ["CM", "Build systems from an approved, hardened baseline.", "Systems aren't built from a hardened baseline, leaving avoidable weaknesses.", "CM-2", "general:L", "intrusion adminerror", "os net"],
  ["CM", "Remove or disable unneeded services, ports and accounts.", "Unneeded services and ports widen the attack surface.", "CM-7", "general:L", "intrusion recon", "os net"],
  ["CM", "Check systems regularly for drift from the approved baseline.", "Configuration drift isn't detected.", "CM-6", "general:M", "adminerror rogueswchange", "os net"],
  ["CM", "Allow only approved applications to run on critical systems.", "Unapproved software can run on critical systems.", "CM-7", "general:H", "malware shadowit ransomware"],
  ["CM", "Keep an accurate inventory of the hardware and software in scope.", "There's no accurate inventory, so unknown assets aren't protected.", "CM-8", "general:L", "shadowit softwaretheft"],
  ["CM", "Track software licences and remove unlicensed software.", "Software licences aren't tracked.", "CM-10", "general:M", "softwaretheft shadowit"],
  ["CM", "Use a formal change process with testing, approval and rollback.", "Changes can be made without testing or approval, risking outages.", "CM-3", "general:L", "softwarechange hwchange adminerror rogueswchange"],
  ["CM", "Assess the security impact of significant changes before making them.", "Significant changes aren't assessed for their security impact.", "CM-4", "general:M", "softwarechange processchange orgchange"],
  ["CM", "Restrict who can make production changes.", "Too many people can make production changes.", "CM-5", "general:L", "rogueswchange privabuse adminerror"],
  ["CM", "Protect against malware on all supported systems.", "Malware protection isn't deployed everywhere it could be.", "SI-3", "general:L", "malware ransomware", "os app"],
  ["CM", "Harden virtual hosts and restrict access to their management consoles.", "Virtual hosts or management consoles aren't hardened.", "CM-6", "virtual:L", "intrusion privabuse"],
  ["CM", "Keep workloads of different sensitivity on separate virtual networks or hosts.", "Workloads of different sensitivity share the same virtual environment.", "SC-7", "virtual:M", "intrusion datadisclose"],
  ["CM", "Protect virtual machine images and snapshots from unauthorized copying.", "Images and snapshots could be copied, exposing their data.", "AC-3", "virtual:L", "datatheft insideraccess"],
  ["CM", "Patch virtualization platforms on a defined schedule.", "Virtualization platforms aren't patched on schedule.", "SI-2", "virtual:L", "intrusion sysfail"],
  ["CM", "Remove unused virtual machines and snapshots regularly.", "Unused virtual machines remain and aren't maintained.", "CM-8", "virtual:L", "intrusion adminerror"],
  ["CM", "Change default settings and credentials on embedded devices.", "Embedded devices may keep vendor defaults.", "CM-6", "embedded:L", "credattack intrusion"],
  ["CM", "Have a way to securely update firmware on embedded devices.", "Embedded firmware can't be updated securely.", "SI-2", "embedded:L", "intrusion rogueswchange"],
  ["CM", "Check the integrity of firmware before it's installed.", "Firmware could be replaced with a tampered version.", "SI-7", "embedded:M", "supplychain rogueswchange"],
  ["CM", "Disable debug ports and unneeded features on embedded devices.", "Debug ports remain open on embedded devices.", "CM-7", "embedded:L", "intrusion recon"],
  ["CM", "Isolate embedded devices on their own network segment.", "Embedded devices share a network with general systems.", "SC-7", "embedded:M", "intrusion malware"],
  // Network security
  ["NS", "Keep a current diagram of the network and data flows.", "There's no current network diagram, making weaknesses harder to see.", "CM-8", "general:L", "adminerror recon", "net app"],
  ["NS", "Segment networks by sensitivity and function.", "Networks aren't segmented, so an intruder can move freely.", "SC-7", "general:M", "intrusion malware ransomware", "net app"],
  ["NS", "Use firewalls to allow only the traffic that's needed.", "Firewall rules allow more traffic than needed.", "SC-7", "general:L", "intrusion recon", "net"],
  ["NS", "Review firewall rules at least once a year.", "Firewall rules aren't reviewed, so old exceptions build up.", "CA-9", "general:L", "intrusion adminerror", "net"],
  ["NS", "Use intrusion detection or prevention on key network paths.", "Network attacks aren't detected on key paths.", "SI-4", "general:M external:L", "intrusion recon malware", "net app"],
  ["NS", "Secure wireless networks with current encryption and separate guest access.", "Wireless networks aren't adequately secured or separated.", "AC-18", "general:L", "intercept intrusion", "net"],
  ["NS", "Control which devices can connect to the internal network.", "Unknown devices can connect to the internal network.", "IA-3", "general:M", "intrusion shadowit", "net"],
  ["NS", "Sign or secure network management traffic and use secure protocols.", "Devices are managed over insecure protocols.", "SC-8", "general:L", "intercept trafficmod", "net"],
  ["NS", "Filter outbound traffic to limit data leaving and malware calling home.", "Outbound traffic isn't filtered.", "SC-7", "general:M external:L", "malware datatheft", "net app"],
  ["NS", "Protect domain name services from spoofing and misuse.", "Name services could be spoofed to misdirect users.", "SC-20", "external:M internet:L", "sitespoof trafficmod", "net app"],
  ["NS", "Filter email and web traffic for known threats.", "Email and web traffic isn't filtered for threats.", "SI-8", "external:L", "phishing malware", "net app"],
  ["NS", "Place internet-facing systems in a protected network zone.", "Internet-facing systems sit directly on internal networks.", "SC-7", "internet:L", "intrusion dos"],
  ["NS", "Use denial-of-service protection on internet-facing services.", "Internet services aren't protected from denial-of-service attacks.", "SC-5", "internet:L", "dos overload"],
  ["NS", "Use a web application firewall in front of internet-facing applications.", "No web application firewall protects internet-facing applications.", "SC-7", "internet:L", "intrusion webtamper"],
  ["NS", "Scan internet-facing systems from outside at least monthly.", "External exposure isn't checked regularly.", "RA-5", "internet:L", "recon intrusion"],
  ["NS", "Require a documented business reason and approval for every external connection.", "External connections aren't documented and approved.", "CA-3", "external:L", "intrusion supplychain"],
  ["NS", "Encrypt all traffic between sites or with external parties.", "Traffic to external parties or sites isn't fully encrypted.", "SC-8", "external:L", "intercept trafficmod"],
  ["NS", "Use redundant network links for important connections.", "A single link failure could cut off important services.", "SC-5", "external:H", "commsfail"],
  // Secure development
  ["SD", "Build security requirements into every project from the start.", "Security requirements aren't defined early, so they're costly to add later.", "SA-3", "general:L", "appfail intrusion", "app"],
  ["SD", "Model threats for significant new features.", "New features aren't threat modeled.", "SA-11", "general:M", "intrusion appfail", "app"],
  ["SD", "Train developers in secure coding each year.", "Developers haven't had recent secure coding training.", "AT-3", "general:M", "appfail intrusion", "app"],
  ["SD", "Use peer code review before code goes to production.", "Code reaches production without peer review.", "SA-11", "general:L", "appfail rogueswchange", "app"],
  ["SD", "Scan code automatically for security flaws.", "Code isn't scanned for security flaws.", "SA-11", "general:M", "intrusion appfail", "app"],
  ["SD", "Scan third-party components for known vulnerabilities and licence issues.", "Third-party components aren't checked for known vulnerabilities.", "SR-3", "general:L", "supplychain intrusion", "app"],
  ["SD", "Keep a software bill of materials for important applications.", "There's no list of the components inside important applications.", "SR-4", "general:H", "supplychain", "app"],
  ["SD", "Separate development, test and production environments.", "Environments aren't separated, so changes could reach production by mistake.", "CM-4", "general:L", "adminerror softwarechange", "app"],
  ["SD", "Protect source code and restrict who can change it.", "Source code isn't properly protected.", "CM-5", "general:L", "softwaretheft rogueswchange", "app"],
  ["SD", "Keep secrets out of source code and scan to catch mistakes.", "Secrets could be left in source code.", "IA-5", "general:L", "credtheft", "app"],
  ["SD", "Sign releases and verify them in the deployment pipeline.", "Releases aren't signed, so a tampered build could be deployed.", "SI-7", "general:M", "supplychain rogueswchange", "app"],
  ["SD", "Test applications for security before significant releases.", "Applications aren't security tested before release.", "CA-8", "general:M internet:L", "intrusion webtamper", "app"],
  ["SD", "Handle errors without revealing sensitive details.", "Error messages could reveal sensitive details.", "SI-11", "general:L", "recon", "app"],
  ["SD", "Validate all input on the server to stop injection attacks.", "Input isn't fully validated, allowing injection attacks.", "SI-10", "web:L", "intrusion datatamper webtamper", "app"],
  ["SD", "Protect web sessions with secure, expiring tokens.", "Web sessions could be hijacked.", "SC-23", "web:L", "impersonate intercept", "app"],
  ["SD", "Set browser security headers such as a content security policy.", "Browser protections aren't set, leaving users exposed to script attacks.", "SC-18", "web:L", "webtamper sitespoof", "app"],
  ["SD", "Authenticate and authorize every API request.", "API requests may not be fully authenticated or authorized.", "AC-3", "web:L", "intrusion insideraccess", "app"],
  ["SD", "Rate-limit APIs and sign-in pages.", "APIs and sign-in pages aren't rate limited.", "SC-5", "web:M internet:L", "dos credattack overload", "app"],
  ["SD", "Check file uploads for type, size and malware.", "File uploads aren't checked.", "SI-3", "web:M", "malware webtamper", "app"],
  ["SD", "Monitor website content for unauthorized changes.", "Unauthorized changes to website content wouldn't be noticed.", "SI-7", "web:H internet:M", "webtamper", "app"],
  ["SD", "Protect the organization's brand by monitoring for fake websites.", "Fake websites imitating the service wouldn't be noticed.", "SI-4", "internet:M", "sitespoof phishing", "app"],
  // Threat and vulnerability management
  ["VM", "Scan systems for vulnerabilities at least monthly.", "Systems aren't regularly scanned for vulnerabilities.", "RA-5", "general:L", "intrusion malware"],
  ["VM", "Patch critical vulnerabilities within a defined time.", "There's no time limit for patching, so known flaws stay open.", "SI-2", "general:L", "intrusion malware ransomware"],
  ["VM", "Prioritize fixes using exploit information and business impact.", "Fixes aren't prioritized by real-world risk.", "RA-5", "general:M", "intrusion ransomware"],
  ["VM", "Record and approve exceptions when a fix can't be applied.", "Unpatched systems have no recorded exception or compensating control.", "CA-5", "general:L", "intrusion"],
  ["VM", "Have an independent penetration test at least once a year.", "No independent penetration test has been done recently.", "CA-8", "general:H internet:M", "intrusion recon"],
  ["VM", "Subscribe to threat intelligence relevant to the technology in use.", "Relevant threat information isn't being followed.", "PM-16", "general:M", "intrusion supplychain"],
  ["VM", "Monitor systems around the clock for security events.", "Security events may not be seen outside business hours.", "SI-4", "general:H", "intrusion ransomware malware"],
  ["VM", "Use endpoint detection and response on supported systems.", "Endpoints lack detection and response tools.", "SI-4", "general:M", "malware ransomware intrusion", "app os"],
  ["VM", "Keep an incident response plan and practice it each year.", "The incident response plan is missing or untested.", "IR-3", "general:L", "ransomware intrusion datatheft"],
  ["VM", "Train staff to recognize phishing and report it.", "Staff aren't trained to recognize phishing.", "AT-2", "general:L", "phishing usererror credshare"],
  ["VM", "Replace software and hardware before vendor support ends.", "Unsupported technology remains in use.", "SA-22", "general:L", "intrusion sysfail hwfail"],
  // Vendor and cloud management
  ["VC", "Assess a third party's security before contracting and at least every year.", "Third parties aren't assessed before or during the contract.", "SR-6", "thirdParty:L", "supplychain datadisclose"],
  ["VC", "Include security, breach notification and audit rights in contracts.", "Contracts lack security terms, breach notice or audit rights.", "SR-3", "thirdParty:L", "supplychain datadisclose"],
  ["VC", "Obtain and review independent assurance reports such as SOC 2.", "Independent assurance reports aren't reviewed.", "SA-9", "thirdParty:L cloud:L", "supplychain"],
  ["VC", "Limit third-party access to what's needed and only when it's needed.", "Third parties have wider or longer access than they need.", "AC-6", "thirdParty:L", "supplychain insideraccess"],
  ["VC", "Require named accounts and multi-factor authentication for third-party staff.", "Third-party staff may use shared accounts or no second factor.", "IA-2", "thirdParty:L", "credshare supplychain"],
  ["VC", "Record and review what third-party administrators do.", "Third-party administrator actions aren't reviewed.", "AU-6", "thirdParty:M", "supplychain privabuse"],
  ["VC", "Have an exit plan to get data back and remove it from the third party.", "There's no plan to recover and remove data at the end of the contract.", "SA-9", "thirdParty:M cloud:L", "orgchange datadisclose"],
  ["VC", "Confirm the third party's own suppliers are held to the same standards.", "The supplier's own suppliers aren't covered.", "SR-3", "thirdParty:H", "supplychain"],
  ["VC", "Define who's responsible for each security task with the cloud provider.", "Security responsibilities with the cloud provider aren't documented.", "SA-9", "cloud:L", "adminerror"],
  ["VC", "Check that data stays in approved regions.", "Data could be stored outside approved regions.", "SA-9", "cloud:L", "datadisclose"],
  ["VC", "Connect cloud administration to single sign-on and multi-factor authentication.", "Cloud administration isn't protected by SSO and a second factor.", "IA-2", "cloud:L", "credattack privabuse"],
  ["VC", "Monitor cloud settings continuously for insecure configuration.", "Insecure cloud settings wouldn't be noticed.", "CM-6", "cloud:L", "adminerror datadisclose"],
  ["VC", "Send cloud audit logs to central monitoring.", "Cloud activity isn't centrally monitored.", "AU-6", "cloud:L", "intrusion insideraccess"],
  ["VC", "Control encryption keys for sensitive cloud data where possible.", "Sensitive cloud data relies only on provider-managed keys.", "SC-12", "cloud:M", "datadisclose cryptoattack"],
  ["VC", "Back up cloud data independently of the provider's own service.", "Cloud data has no independent backup.", "CP-9", "cloud:M", "ransomware usererror commsfail"],
  ["VC", "Confirm whether the vendor uses customer data to train AI, and restrict it by contract.", "Vendors may use the organization's data to train AI.", "SA-9", "thirdParty:M cloud:M", "datadisclose"],
  // Physical and environmental security
  ["PE", "Restrict physical access to equipment rooms and keep a record of who enters.", "Physical access to equipment isn't restricted or recorded.", "PE-3", "general:L", "devicetheft sitefail", "os net"],
  ["PE", "Escort and record visitors in secure areas.", "Visitors aren't escorted in secure areas.", "PE-8", "general:M", "devicetheft sabotage", "os net"],
  ["PE", "Use cameras or alarms at sensitive sites.", "Sensitive sites lack cameras or alarms.", "PE-6", "general:M", "devicetheft sabotage", "os net"],
  ["PE", "Protect equipment against fire, flood and temperature extremes.", "Equipment isn't protected from environmental damage.", "PE-13", "general:L", "disaster envfail sitefail", "os net"],
  ["PE", "Use backup power for equipment that needs to stay running.", "Important equipment has no backup power.", "PE-11", "general:M", "powerfail", "os net"],
  ["PE", "Maintain cooling and environmental support systems.", "Cooling and support systems aren't maintained.", "PE-14", "general:M", "envfail", "os net"],
  ["PE", "Have an alternate site or recovery option for critical services.", "No alternate site exists for critical services.", "CP-7", "general:H", "sitefail disaster", "os net"],
  ["PE", "Maintain equipment under a schedule from qualified people.", "Equipment isn't maintained on a schedule.", "MA-2", "general:L", "hwfail", "os net"],
  // OT asset and configuration management
  ["OA", "Keep a complete inventory of OT assets, including firmware versions.", "OT assets aren't fully inventoried, so vulnerable devices can be missed.", "CM-8", "general:L", "hwfail adminerror", "ot"],
  ["OA", "Classify OT assets by how critical they are to safety and operations.", "OT assets aren't ranked by criticality.", "RA-2", "general:L", "sitefail", "ot"],
  ["OA", "Document an approved configuration baseline for every OT asset.", "OT assets have no approved baseline.", "CM-2", "general:L", "adminerror hwchange", "ot"],
  ["OA", "Back up OT configurations, logic and firmware, and store them safely.", "OT configurations aren't backed up.", "CP-9", "general:L", "ransomware hwfail", "ot"],
  ["OA", "Use a formal OT change process that includes safety review.", "OT changes aren't reviewed for safety and operational effects.", "CM-3", "general:L", "hwchange softwarechange adminerror", "ot"],
  ["OA", "Test OT changes offline before they reach production.", "OT changes aren't tested before production.", "CM-4", "general:M", "hwchange softwarechange", "ot"],
  ["OA", "Detect unauthorized changes to controller logic and firmware.", "Unauthorized logic or firmware changes wouldn't be detected.", "SI-7", "general:M", "rogueswchange sabotage", "ot"],
  ["OA", "Disable unused services, ports and protocols on OT devices.", "OT devices run unneeded services and ports.", "CM-7", "general:L", "intrusion recon", "ot"],
  ["OA", "Control and scan removable media and maintenance laptops before OT use.", "Removable media and maintenance laptops can bring malware into OT.", "MP-7", "general:L", "malware", "ot"],
  ["OA", "Keep a replacement plan and spares for end-of-life OT systems.", "End-of-life OT systems have no replacement plan or spares.", "SA-22", "otEol:L", "hwfail sysfail", "ot"],
  ["OA", "Add compensating protection around OT systems that can no longer be patched.", "Unsupported OT systems have no compensating protection.", "SC-7", "otEol:L", "intrusion malware", "ot"],
  // OT data protection
  ["OD", "Classify and protect OT data, including sensitive operational information.", "Sensitive OT information isn't classified or protected.", "RA-2", "general:L", "datadisclose datatheft", "ot"],
  ["OD", "Encrypt sensitive OT data when it crosses untrusted networks.", "OT data crosses untrusted networks unencrypted.", "SC-8", "general:M external:L", "intercept trafficmod", "ot"],
  ["OD", "Check the integrity of operational data and commands.", "Operational data or commands could be altered unnoticed.", "SI-7", "general:M", "datatamper trafficmod", "ot"],
  ["OD", "Test restoring OT backups at least once a year.", "OT backups haven't been tested.", "CP-9", "general:L", "ransomware hwfail", "ot"],
  // OT identity and access
  ["OI", "Give each person a unique OT account wherever the system supports it.", "Shared OT accounts make actions untraceable.", "IA-2", "general:L", "credshare insideraccess", "ot"],
  ["OI", "Document any shared OT accounts and restrict who can use them.", "Shared OT accounts aren't documented or restricted.", "AC-2", "general:L", "credshare", "ot"],
  ["OI", "Change default credentials on all OT devices.", "OT devices may still have default credentials.", "IA-5", "general:L", "credattack intrusion", "ot"],
  ["OI", "Give OT users only the access their role needs.", "OT users have more access than they need.", "AC-6", "general:L", "insideraccess privabuse", "ot"],
  ["OI", "Keep OT access separate from corporate accounts.", "A corporate account compromise could reach OT.", "AC-3", "general:M", "intrusion credtheft", "ot"],
  ["OI", "Review OT access at least every quarter.", "OT access isn't reviewed regularly.", "AC-2", "general:L", "insideraccess", "ot"],
  ["OI", "Remove OT access within one day of someone leaving.", "Leavers may keep OT access.", "AC-2", "general:L", "insideraccess", "ot"],
  ["OI", "Require multi-factor authentication for all remote OT access.", "Remote OT access doesn't require a second factor.", "IA-2", "general:L external:L", "credattack intrusion", "ot"],
  ["OI", "Approve, monitor and record vendor remote sessions into OT.", "Vendor remote sessions into OT aren't controlled or recorded.", "AC-17", "general:L thirdParty:L", "supplychain intrusion", "ot"],
  ["OI", "Keep emergency access available for safety-critical operations, and review its use.", "Emergency access is missing or its use isn't reviewed.", "AC-2", "general:M", "adminerror", "ot"],
  // OT infrastructure security
  ["ON", "Separate OT networks from corporate networks with a firewall and a buffer zone.", "OT isn't properly separated from the corporate network.", "SC-7", "general:L", "intrusion malware ransomware", "ot"],
  ["ON", "Block direct internet access from OT networks.", "OT networks can reach the internet directly.", "SC-7", "general:L internet:L", "intrusion malware", "ot"],
  ["ON", "Divide OT networks into zones by function and safety.", "OT networks aren't divided into zones.", "SC-7", "general:M", "intrusion sabotage", "ot"],
  ["ON", "Isolate safety systems from control systems.", "Safety systems aren't isolated from control systems.", "SC-3", "general:L", "sabotage sitefail", "ot"],
  ["ON", "Allow only the protocols and traffic OT needs, by default-deny rules.", "OT firewalls allow more traffic than needed.", "SC-7", "general:L", "intrusion recon", "ot"],
  ["ON", "Use one-way gateways for the most critical data flows out of OT.", "Critical OT zones have two-way connections where one-way would do.", "SC-7", "general:H", "intrusion", "ot"],
  ["ON", "Route all remote OT access through a secure jump host.", "Remote OT access doesn't go through a controlled jump host.", "AC-17", "general:L external:L", "intrusion", "ot"],
  ["ON", "Disable remote access to OT when it's not needed.", "Remote OT access stays on when it's not needed.", "AC-17", "general:M", "intrusion", "ot"],
  ["ON", "Keep a current diagram of OT networks and connections.", "OT network diagrams are missing or out of date.", "CM-8", "general:L", "adminerror", "ot"],
  ["ON", "Review OT firewall rules at least once a year.", "OT firewall rules aren't reviewed.", "CA-9", "general:L", "intrusion", "ot"],
  ["ON", "Secure wireless OT connections or don't use them.", "Wireless connections in OT aren't secured.", "AC-18", "general:L", "intercept intrusion", "ot"],
  ["ON", "Provide physical protection for OT devices, cabinets and network ports.", "OT devices or ports are physically exposed.", "PE-3", "general:L", "sabotage devicetheft", "ot"],
  ["ON", "Provide backup power and redundancy for critical OT systems.", "Critical OT systems lack backup power or redundancy.", "PE-11", "general:M", "powerfail hwfail commsfail", "ot"],
  ["ON", "Allow only approved applications on OT workstations and servers.", "Unapproved software can run on OT workstations.", "CM-7", "general:M", "malware shadowit", "ot"],
  ["ON", "Protect OT time sources so that logs and control stay accurate.", "OT time sources aren't protected.", "AU-8", "general:H", "sysfail", "ot"],
  ["ON", "Define how operations continue manually if control systems are lost.", "There's no plan for manual operation if control systems fail.", "CP-2", "general:L", "ransomware sitefail sysfail", "ot"],
  // OT security operations
  ["OS", "Monitor OT networks for unusual traffic and commands, passively where needed.", "OT networks aren't monitored for unusual activity.", "SI-4", "general:L", "intrusion sabotage", "ot"],
  ["OS", "Collect OT logs centrally where the devices support it.", "OT logs aren't collected centrally.", "AU-6", "general:M", "intrusion insideraccess", "ot"],
  ["OS", "Send OT alerts to staff who understand both security and operations.", "OT alerts don't reach people able to act on them.", "IR-4", "general:M", "intrusion adminerror", "ot"],
  ["OS", "Keep an OT-specific incident response plan and practice it each year.", "There's no practiced OT incident response plan.", "IR-8", "general:L", "ransomware sabotage", "ot"],
  ["OS", "Coordinate OT incidents with safety and engineering teams.", "OT incident response isn't coordinated with safety and engineering.", "IR-4", "general:L", "sitefail", "ot"],
  ["OS", "Train OT staff on cybersecurity for their systems every year.", "OT staff don't get cybersecurity training for their systems.", "AT-3", "general:L", "usererror phishing", "ot"],
  ["OS", "Check that regulatory OT reporting requirements, such as NERC CIP, are met.", "Regulatory OT reporting requirements haven't been checked.", "CA-2", "general:M", "sitefail", "ot"],
  ["OS", "Screen people who have privileged OT access, where the law allows.", "People with privileged OT access haven't been screened.", "PS-3", "general:M", "sabotage insideraccess", "ot"],
  // OT vulnerability management
  ["OV", "Track vendor security notices for all OT products in use.", "Vendor security notices for OT aren't tracked.", "RA-5", "general:L", "intrusion", "ot"],
  ["OV", "Assess OT vulnerabilities passively or in a test bed, not live on fragile devices.", "OT vulnerability checks could disrupt fragile devices, or aren't done.", "RA-5", "general:L", "intrusion hwfail", "ot"],
  ["OV", "Assess and test OT patches with the vendor before applying them.", "OT patches aren't tested before installation.", "SI-2", "general:L", "softwarechange", "ot"],
  ["OV", "Patch OT in planned outage windows according to risk.", "OT isn't patched on a risk-based schedule.", "SI-2", "general:L", "intrusion malware", "ot"],
  ["OV", "Record compensating controls when an OT patch can't be applied.", "OT systems that can't be patched have no recorded compensating controls.", "CA-5", "general:L otEol:L", "intrusion", "ot"],
  ["OV", "Protect OT systems against malware in a way that's approved by the vendor.", "OT systems have no vendor-approved malware protection.", "SI-3", "general:L", "malware ransomware", "ot"],
  ["OV", "Run an independent OT security assessment at least every three years.", "No independent OT security assessment has been done.", "CA-2", "general:M", "intrusion", "ot"],
  ["OV", "Verify the source and integrity of OT software before installing it.", "OT software could be installed without checking where it came from.", "SR-11", "general:M embedded:L", "supplychain", "ot"],
];

const counters = {};
export const CONTROLS = DEFINED.map(([code, text, gap, nist, rules, threats, assets = "app os net"]) => {
  counters[code] = (counters[code] || 0) + 1;
  return {
    id: `${code}-${String(counters[code]).padStart(2, "0")}`,
    section: CONTROL_SECTIONS[code], text, gap, nist,
    rules: rules.split(" ").map((r) => { const [on, tier] = r.split(":"); return { on, tier }; }),
    threats: threats.split(" "), assets: assets.split(" "),
  };
});
