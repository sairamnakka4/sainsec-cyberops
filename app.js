const R={
"Microsoft Entra":"https://entra.microsoft.com/","Microsoft Learn":"https://learn.microsoft.com/","Microsoft Sentinel":"https://azure.microsoft.com/products/microsoft-sentinel/","Defender XDR":"https://security.microsoft.com/","Sysinternals":"https://learn.microsoft.com/sysinternals/","VirusTotal":"https://www.virustotal.com/","AbuseIPDB":"https://www.abuseipdb.com/","GreyNoise":"https://www.greynoise.io/","Shodan":"https://www.shodan.io/","OTX":"https://otx.alienvault.com/","ThreatFox":"https://threatfox.abuse.ch/","URLScan":"https://urlscan.io/","MalwareBazaar":"https://bazaar.abuse.ch/","Hybrid Analysis":"https://www.hybrid-analysis.com/","ANY.RUN":"https://any.run/","Wireshark":"https://www.wireshark.org/","ATT&CK":"https://attack.mitre.org/","CyberChef":"https://gchq.github.io/CyberChef/","OWASP":"https://owasp.org/","PortSwigger":"https://portswigger.net/web-security","CISA KEV":"https://www.cisa.gov/known-exploited-vulnerabilities-catalog","NVD":"https://nvd.nist.gov/","CISA IR":"https://www.cisa.gov/topics/cyber-threats-and-advisories/incident-response","NIST 800-61":"https://csrc.nist.gov/pubs/sp/800/61/r2/final","Volatility":"https://volatilityfoundation.org/","Autopsy":"https://www.autopsy.com/"};
const data=[
["Identity & Account Security",[
["Suspicious Sign-in","Unexpected authentication that needs identity, device, location and method validation.","Entra Sign-in Logs, Identity Protection, VPN, Defender","User → IP → device → auth method → geo → successful login","Unfamiliar IP/ASN; impossible location; new device; risky sign-in; success after failures","Verify with user; review CA/MFA; restrict risky sessions where policy permits","If compromise suspected: revoke sessions/tokens, reset credential, review MFA methods, scope follow-on activity","Entra","Microsoft Entra"],
["Password Spray","Many accounts receive authentication failures associated with a common source/pattern.","Entra Sign-in, Windows 4625/4776, VPN","Source IP → users → time window → successful sign-in → MFA","Many users targeted; low attempts/user; same source; success after failures","Block/contain source as appropriate; enforce MFA; watch privileged users","Revoke sessions, reset affected credentials, identify successful targets, hunt source across telemetry","Entra","AbuseIPDB"],
["Brute Force Login","Repeated authentication attempts against one account/service.","Entra, Windows, VPN, SSH","Account → source → failure count → success → lockout","High failure burst; multiple sources; success immediately after failures; unusual geo","Rate-limit/lock out per policy; verify account owner; monitor related accounts","Reset credential, revoke sessions, inspect endpoint and post-auth activity","Entra","Microsoft Learn"],
["MFA Fatigue / Push Bombing","Repeated MFA prompts may be an attempt to induce an approval.","Entra auth logs, audit logs","User → MFA method → prompt count → IP → device → approval","Prompt storm; unusual source/device; approval after repeated denies","Contact user through trusted channel; educate; strengthen number matching/phishing-resistant MFA","Revoke sessions, reset auth methods as appropriate, review sign-ins and persistence","Entra","Microsoft Entra"],
["MFA Method Added/Changed","New authentication method can be legitimate or account-takeover persistence.","Entra Audit Logs","Actor → user → method → timestamp → preceding sign-in","Method added immediately after risky sign-in; unfamiliar actor/IP; privileged target","Validate change; alert on privileged identities; require approved change process","Remove unauthorized method, revoke sessions, reset credentials and investigate actor","Entra","Microsoft Entra"]]],
["Phishing & Email Security",[
["Spear Phishing","Targeted email attempts to induce a click, credential disclosure or execution.","Defender for Office 365, message trace, headers","Sender → URL → attachment → recipients → post-delivery activity","Lookalike domain; urgent request; mismatched links; unusual sender; credential page","Report/quarantine message; warn recipients; block malicious infrastructure","Remove messages, reset exposed credentials, revoke sessions, scope recipients and endpoint activity","Defender XDR","URLScan"],
["Malicious Attachment","Attachment may execute code or deliver malware.","Defender, EDR, sandbox","Hash → filename → process → parent → network","Rare file; macros/scripts; unsigned binary; child process from Office; outbound connection","Quarantine; block hash/domain; prevent execution where controls support it","Isolate host, collect hash/timeline, remove payload, reset exposed credentials if needed","VirusTotal","Defender XDR"],
["Mailbox Rule Manipulation","Unexpected forwarding or inbox rules may support persistence or collection.","M365 Audit / Exchange audit","User → rule → destination → creator → timestamp","External forwarding; hidden/odd rule name; rule created after suspicious login","Disable suspicious rule; review mailbox audit","Revoke sessions, reset credential, remove rule, review sent mail and data access","Defender XDR","Microsoft Learn"],
["Business Email Compromise","Trusted mailbox activity is used for fraudulent or unauthorized communication.","Defender, Entra, audit logs","Sign-in → mailbox changes → forwarding → sent mail → recipients","New device/location; finance/vendor change; unusual recipients; forwarding","Validate request out-of-band; alert finance/users","Revoke sessions, reset credential, remove persistence, investigate affected mailboxes","Defender XDR","Microsoft Entra"]]],
["Endpoint & Malware",[
["Malware Detection","EDR detects a suspicious file or behavior.","Defender, CrowdStrike, endpoint events","Hash → path → process → parent → user → network","Unsigned/rare file; temp/user-writable path; suspicious parent; C2 connection","Isolate when warranted; quarantine; preserve evidence","Contain host, collect evidence, eradicate payload, hunt hash/process/network across estate","Defender XDR","Sysinternals"],
["Ransomware Behavior","Mass modification/encryption-like activity may require rapid containment.","EDR, file/process telemetry","Host → user → process → files → lateral activity","Rapid file changes; ransom note; shadow-copy deletion; unusual admin shares","Isolate affected hosts; protect backups; stop spread","Contain affected systems, preserve volatile evidence, eradicate entry point, validate backups before restore","Defender XDR","CISA IR"],
["Process Injection","One process may inject code into another.","EDR, memory analysis","Source process → target process → user → command line → modules","Unexpected access rights; suspicious source process; unsigned module; unusual parent","Isolate if malicious behavior is corroborated; preserve memory where possible","Capture memory/evidence, terminate malicious chain as appropriate, hunt same technique","ATT&CK","Volatility"]]],
["PowerShell & LOLBins",[
["Encoded PowerShell","Encoded commands need decoding and behavioral validation.","PowerShell logs, EDR, 4688","Command line → decoded content → parent → network","Encoded blob; download/execute chain; Office/browser parent; hidden window","Block/contain malicious script; preserve command line","Decode safely, collect script/process/network evidence, isolate if payload execution is confirmed","CyberChef","Sysinternals"],
["PowerShell Download","PowerShell makes an external request to retrieve content.","PowerShell, proxy, DNS, EDR","URL → domain → process → downloaded file → hash","Rare domain; IP literal; encoded URL; executable/script download","Block destination if malicious; quarantine payload","Isolate host if needed, collect payload/hash, scope other hosts/users","Defender XDR","VirusTotal"],
["PsExec / Remote Service","Remote service execution may be administration or lateral movement.","7045, 4688, EDR","Source → target → account → service → process","Unexpected source/target; privileged account; new service; off-hours","Validate admin activity; restrict lateral movement paths where appropriate","Disable unauthorized account/session, isolate affected hosts, investigate credential use","Sysinternals","ATT&CK"]]],
["Windows Security Events",[
["4624 — Successful Logon","Successful Windows authentication event requiring context.","SecurityEvent 4624, EDR","Account → source → logon type → workstation → process","Rare source; privileged account; unusual logon type; after password spray","Validate user/admin activity; monitor follow-on actions","Revoke/reset credential if compromise suspected; scope source and endpoint","Microsoft Learn","ATT&CK"],
["4625 — Failed Logon","Failed Windows authentication event.","SecurityEvent 4625","Account → source → failure reason → count → 4624 correlation","Burst failures; many users; success after failures; unusual source","Rate-limit/lockout according to policy; investigate source","Reset credential if successful compromise follows; hunt source and target accounts","Microsoft Learn","AbuseIPDB"],
["4688 — Process Creation","Process creation helps reconstruct execution chains.","SecurityEvent 4688, Sysmon, EDR","Process → parent → command line → user → hash","Suspicious parent; LOLBin; encoded command; user-writable path","Contain suspicious process/host when justified; preserve evidence","Collect process tree, command line, hash and network activity; eradicate confirmed payload","Sysinternals","ATT&CK"],
["4740 — Account Lockout","Lockout can result from user error, stale credentials or attack activity.","SecurityEvent 4740","Locked account → caller computer → preceding failures → source","Repeated lockouts; multiple accounts; unusual caller host","Validate user context; investigate common source","Reset credential and investigate source if malicious activity is confirmed","Microsoft Learn","Microsoft Entra"],
["7045 — New Service","New service can be legitimate software or persistence.","System 7045, EDR","Service → binary path → creator → host → process tree","Random service name; temp path; unsigned binary; unexpected creator","Validate software/change; disable unauthorized service carefully","Preserve binary/config, isolate host if malicious, remove persistence after evidence capture","Sysinternals","ATT&CK"]]],
["Network & Firewall",[
["Port Scan / Host Discovery","One source probes many ports or hosts.","Firewall, flow, IDS/IPS","Source → destinations → ports → timing → response","High destination count; sequential ports; repeated probes","Block/rate-limit source where appropriate; validate scanner ownership","Scope source/targets, check endpoint activity and exploitation attempts","Wireshark","Shodan"],
["Suspicious Outbound Connection","Host communicates with unusual external infrastructure.","Firewall, proxy, DNS, EDR","Host → process → destination IP/domain → DNS → bytes","Rare domain; new ASN; beacon-like interval; suspicious process","Block destination if malicious; isolate host based on confidence","Collect process/network evidence, eradicate payload, hunt destination across estate","VirusTotal","AbuseIPDB"],
["Firewall Deny Spike","Sudden increase in denied traffic may indicate scanning, misconfiguration or attack activity.","Firewall logs, flow","Source/destination → port → rule → time series","Burst from one source; many targets; new exposed service","Validate change; tune noisy expected traffic; block confirmed malicious sources","Investigate exposed assets, correlate IDS/endpoint events, document rule/change","Microsoft Learn","Wireshark"]]],
["DNS & Domain Security",[
["DNS Tunneling","DNS queries may be used to move data or maintain C2.","DNS logs, proxy, EDR","Host → domain → query type → length → frequency → response","Long/high-entropy subdomains; high query rate; TXT anomalies; rare domain","Block suspicious domain; increase DNS visibility","Isolate host if corroborated, capture DNS timeline and process/network evidence","Wireshark","VirusTotal"],
["Newly Registered / Rare Domain","Rare or newly observed domains can be benign or malicious and need context.","DNS, proxy, CTI","Domain → age → registrar → users → URL path → process","New domain + credential page; rare across org; suspicious hosting","Block/quarantine based on confidence; warn users","Scope affected hosts/users, remove payload or reset credentials if exposure occurred","URLScan","VirusTotal"]]],
["Active Directory & Privilege",[
["DCSync","Directory replication behavior should be validated against authorized replication principals.","4662, AD audit, DC telemetry","Actor → replication rights → source host → DC → account","Unexpected workstation; non-DC source; unusual account; replication rights not expected","Restrict replication privileges; alert on anomalous replication requests","Contain source, disable/reset compromised identity, investigate DC and credential exposure","ATT&CK","Microsoft Learn"],
["Admin Group Membership Change","Unexpected privileged-group changes can expand access.","4728/4732/4756, AD audit","Actor → added member → group → source → subsequent logons","Privileged group; unexpected actor; off-hours; immediate privileged activity","Use approval workflow; monitor privileged groups; least privilege","Remove unauthorized membership, reset affected credentials, review actions performed","Microsoft Learn","ATT&CK"],
["GPO Modification","Group Policy changes can affect many endpoints and security controls.","AD/GPO audit","Actor → GPO → setting → scope → timestamp","Security setting weakened; script added; unexpected scope; unknown actor","Require change approval; protect privileged GPOs","Revert unauthorized change after evidence capture; scope affected hosts and credentials","Microsoft Learn","ATT&CK"],
["AS-REP Roasting","Authentication requests involving accounts without pre-authentication require validation.","4768, DC logs","Requester → account → encryption type → source host","Unexpected requester; unusual account targeting; non-admin workstation","Require pre-authentication where appropriate; monitor exposed accounts","Reset affected service/user credentials and investigate source host","ATT&CK","Microsoft Learn"],
["Golden/Silver Ticket Indicators","Abnormal Kerberos ticket activity may indicate forged-ticket behavior.","4768/4769, DC telemetry, EDR","Account → ticket lifetime → service → source host → logon","Unusual lifetime; nonexistent account context; ticket use without expected auth","Protect Tier-0 credentials; monitor Kerberos anomalies","Contain affected hosts, rotate relevant secrets/keys as appropriate, scope persistence","ATT&CK","Microsoft Learn"]]],

["Entra ID & SaaS",[
["Service Principal Credential Added","A new application secret/certificate can create persistence.","Entra Audit Logs","Actor → app → credential → source IP → subsequent sign-ins","Unexpected app owner; new secret after risky login; privileged app","Restrict app registration/consent; monitor credential changes","Remove unauthorized credential, revoke tokens, review app permissions and sign-ins","Microsoft Entra","Microsoft Learn"],
["Application Permission Grant","New application permissions can provide broad data access.","Entra Audit, app consent logs","Actor → app → permission → tenant → affected data","High-privilege permission; unfamiliar app; consent by unexpected user","Admin consent workflow; least privilege; periodic app review","Revoke grant, disable app if malicious, revoke sessions/tokens, scope accessed data","Microsoft Entra","Microsoft Learn"],
["Conditional Access Policy Change","Authentication controls may be weakened or bypassed by policy changes.","Entra Audit Logs","Actor → policy → condition/action → old/new value → source","MFA exclusion; broad exclusion; unexpected disablement; privileged actor","Require change approval and monitor policy changes","Restore policy safely, revoke sessions if compromise suspected, investigate actor","Microsoft Entra","Microsoft Learn"],
["External / Guest User Added","Unexpected external identities can create unauthorized access paths.","Entra Audit, directory logs","Actor → guest → inviter → groups/apps → sign-ins","Unknown domain; privileged group; unusual inviter; immediate access","Guest governance, expiry and access reviews","Remove unauthorized guest, revoke sessions, review resources accessed","Microsoft Entra","Microsoft Learn"],
["Legacy Authentication","Legacy protocols can bypass modern authentication controls.","Entra Sign-in Logs","User → client app → protocol → source → result","Legacy protocol for privileged user; repeated failures; unexpected device","Disable legacy authentication where feasible; enforce modern auth","Reset/revoke affected identity and investigate source/device if malicious","Microsoft Entra","Microsoft Learn"]]],

["Network & Lateral Movement",[
["RDP Anomaly","Unexpected RDP access may indicate administration or lateral movement.","4624, 1149, EDR, firewall","Source → destination → account → logon type → process","Rare source; privileged account; unusual time; multiple targets","Restrict RDP exposure; use MFA/VPN and admin controls","Isolate affected hosts, reset exposed credentials, hunt source-to-target activity","ATT&CK","Microsoft Learn"],
["SMB Lateral Movement","SMB connections may represent file access, administration or lateral movement.","5140/5145, firewall, EDR","Source → target → share → account → process","Admin share; unusual workstation-to-workstation access; many targets","Restrict unnecessary SMB; segment networks; protect admin shares","Contain source/target, investigate credential use and transferred files","ATT&CK","Wireshark"],
["SSH Brute Force","Repeated SSH authentication failures may indicate attack or misconfiguration.","Linux auth logs, firewall, EDR","Source → account → failure count → success → command activity","Burst failures; many usernames; success after failures","Key-based auth, rate limits, restrict exposure","Reset/rotate credentials/keys, terminate malicious sessions, inspect commands and persistence","ATT&CK","AbuseIPDB"],
["VPN Login Anomaly","VPN authentication differs from normal user/device/location patterns.","VPN, Entra, MFA, endpoint","User → source IP → device → MFA → session duration","Impossible location; new device; repeated MFA; concurrent sessions","Require MFA/device compliance; monitor risky VPN access","Revoke VPN/session access, reset credentials, investigate endpoint and identity","Microsoft Entra","AbuseIPDB"],
["Lateral Movement Burst","One account or host reaches multiple internal systems unusually quickly.","Firewall, EDR, 4624, 5140, 4688","Source host → targets → account → protocol → process","Many targets; privileged identity; short time window; remote execution","Segment networks; restrict admin paths; use dedicated admin accounts","Contain source host/account, revoke sessions, hunt all targets and remote execution artifacts","ATT&CK","Wireshark"]]],

["Firewall / IDS / IPS",[
["IDS Signature Alert","An IDS signature indicates traffic matching a known suspicious pattern.","IDS/IPS, firewall, packet capture","Source → destination → signature → payload/context → outcome","Repeated exploit attempts; internal target; successful follow-on traffic","Validate exposure; tune false positives only with evidence","Block/contain as appropriate, inspect target endpoint and exploit indicators","Wireshark","CISA KEV"],
["IPS Block Event","Traffic was blocked by an intrusion-prevention control.","IPS, firewall, endpoint","Source → target → signature → action → repeated attempts","Repeated source; critical asset target; different ports","Maintain blocking and validate target exposure","Check whether any attempt succeeded elsewhere; hunt source and target telemetry","Wireshark","CISA KEV"],
["Firewall Rule Change","Security policy changes can create unintended exposure.","Firewall audit/configuration logs","Actor → rule → old/new value → source → affected zone","Any-to-any rule; internet exposure; unknown actor; disabled deny","Change approval, configuration backup, least privilege","Revert unauthorized change after evidence capture and investigate actor","Microsoft Learn","CISA IR"],
["Unexpected Public Exposure","A service becomes reachable from the internet unexpectedly.","Firewall, cloud NSG, asset inventory","Asset → public IP → port → rule → owner","New public IP; admin port exposed; unknown owner","Restrict ingress; review NSG/firewall policy","Remove exposure, inspect service for compromise, rotate credentials if needed","CISA KEV","NVD"]]],

["Web / Proxy / HTTP",[
["Malicious URL Access","A user or host accessed a URL associated with suspicious activity.","Proxy, DNS, browser, Defender","User → URL → redirects → process → download","Credential page; exploit kit; rare/new domain; download","Block URL/domain; warn affected users","Reset credentials if submitted, isolate endpoint if payload executed, scope recipients","URLScan","VirusTotal"],
["HTTP Beaconing","Repeated outbound HTTP/S connections at regular intervals may indicate C2.","Proxy, firewall, DNS, EDR","Host → process → destination → interval → bytes","Regular timing; rare domain/IP; suspicious process; small periodic requests","Block destination; investigate process ownership","Isolate host if corroborated, capture network/process evidence, eradicate payload","Wireshark","GreyNoise"],
["Large Outbound Upload","Unusual outbound data volume may indicate exfiltration or legitimate transfer.","Proxy, firewall, cloud audit, DLP","User → host → destination → bytes → file/service","Large transfer to unknown service; off-hours; sensitive data path","Validate business need; DLP controls; restrict unsanctioned storage","Contain account/host, preserve evidence, identify data scope and destination","Microsoft Purview","Wireshark"],
["Web Shell Traffic","HTTP traffic may interact with a server-side shell.","Web logs, WAF, EDR, process telemetry","URL path → request → process → parent → file","Encoded parameters; unusual POST; child shell process; rare endpoint","Patch exposed app; restrict admin paths; WAF controls","Isolate server, preserve web/app/process evidence, remove persistence after scoping","OWASP","CISA IR"]]],

["Cloud / Azure",[
["Azure Admin Activity Anomaly","Unexpected privileged Azure control-plane activity needs validation.","Azure Activity Log, Entra audit","Actor → subscription → resource → action → source IP","Privileged action from unusual identity/location; destructive change","Privileged access controls, MFA, JIT/PIM and alerting","Revoke sessions/credentials, reverse unauthorized changes safely, scope resource access","Microsoft Learn","Microsoft Entra"],
["NSG Rule Change","Network Security Group changes can expose cloud resources.","Azure Activity Log, NSG diagnostics","Actor → NSG → old/new rule → resource → source","Internet-wide inbound; admin ports; unknown actor","Restrict admin ports; change approval","Revert unauthorized rule, inspect exposed service and access logs","Microsoft Learn","CISA KEV"],
["Storage Exposure","Storage configuration may unintentionally expose data.","Azure Activity Log, Storage logs","Actor → account → public access → containers → reads","Public access; anonymous reads; unusual download volume","Disable public access where not required; least privilege","Remove exposure, preserve access logs, identify data accessed and rotate secrets if needed","Microsoft Learn","Microsoft Purview"],
["Key Vault Access Anomaly","Unexpected secret/key/certificate access may indicate identity compromise.","Key Vault logs, Entra, Activity Log","Identity → vault → object → operation → source","Rare identity; bulk secret reads; unusual location; service principal anomaly","Least privilege, private endpoints, monitoring","Revoke identity access, rotate affected secrets/keys as appropriate, scope dependent resources","Microsoft Learn","Microsoft Entra"],
["Cloud Shell / Unusual Region","Interactive cloud activity from an unexpected region or environment requires validation.","Azure Activity Log, Entra, Cloud Shell logs","User → region → resource → command/context","New region; privileged command; unusual source/device","Conditional access and privileged controls","Revoke session, review commands/resources, reset identity if compromised","Microsoft Learn","Microsoft Entra"]]],

["Data Loss / Insider Risk",[
["Sensitive Data Download","Large or unusual downloads from sensitive repositories require context.","DLP, Purview, storage audit, proxy","User → resource → files → volume → destination","Off-hours; unusual volume; external destination; sensitive labels","DLP policies, least privilege, access reviews","Contain account/session, preserve audit data, determine data scope and notify response team","Microsoft Purview","Microsoft Learn"],
["USB / Removable Media Anomaly","Unexpected sensitive-file transfer to removable media may require investigation.","Endpoint/DLP telemetry","User → device → files → volume → timestamp","Sensitive labels; unusual user/device; large transfer","Device control and DLP policies","Contain account/endpoint as appropriate, preserve evidence and determine data scope","Microsoft Purview","Defender XDR"],
["Cloud Storage Exfiltration","Sensitive files may be copied to an external or unsanctioned storage service.","Proxy, DLP, endpoint, cloud audit","User → files → service → destination → volume","Unsanctioned domain; compressed archive; large upload","Block unsanctioned storage; DLP and CASB controls","Revoke session, block destination, preserve logs and determine affected data","Microsoft Purview","Defender XDR"]]],

["Persistence & Execution",[
["Scheduled Task Persistence","Unexpected scheduled tasks may provide recurring execution.","Task Scheduler logs, 4698, EDR","Creator → task → command → trigger → file","Random name; user-writable path; script/binary; unusual creator","Restrict task creation; monitor privileged task changes","Preserve task/config, disable malicious task after evidence capture, remove payload and hunt","Sysinternals","ATT&CK"],
["New Windows Service Persistence","A new service may be legitimate software or persistence.","7045, EDR, service configuration","Creator → service → binary → host → process","Unsigned binary; temp path; unknown service; unusual account","Application allowlisting and service monitoring","Disable malicious service after evidence capture, isolate host if warranted, hunt binary/hash","Sysinternals","ATT&CK"],
["Registry Run Key Persistence","Run/RunOnce entries can provide logon-triggered execution.","Registry, EDR, Sysmon","User → key → value → binary → creator","Unknown binary; user-writable path; script interpreter","Monitor persistence locations; application controls","Remove unauthorized persistence after evidence capture, quarantine payload, scope other hosts","Sysinternals","ATT&CK"],
["Linux Cron Persistence","Unexpected cron entries can execute recurring commands.","cron logs, auditd, EDR","User → cron → command → file → host","Encoded command; network download; unexpected user","Restrict write access; monitor cron changes","Preserve cron/file evidence, remove persistence after scoping, rotate compromised credentials","ATT&CK","Microsoft Learn"],
["SSH Authorized Key Change","Unauthorized SSH keys can provide persistent access.","auth logs, file integrity, auditd","User → key → creator → source IP → subsequent login","Unknown key; unexpected creator; new privileged key","Protect authorized_keys, use managed access and key rotation","Remove unauthorized key, terminate sessions, rotate credentials and investigate source","ATT&CK","Microsoft Learn"]]],

["Vulnerability & Exposure",[
["Known Exploited Vulnerability","A vulnerable asset matches a vulnerability known to be exploited in the wild.","Asset inventory, scanner, CISA KEV, vendor advisories","Asset → CVE → exposure → exploitability → observed activity","Internet exposure; KEV-listed CVE; exploit telemetry","Patch/mitigate; restrict exposure; compensating controls","Check for exploitation evidence, isolate affected asset if compromise suspected, preserve logs","CISA KEV","NVD"],
["Exploit Attempt","Traffic appears to target a known application weakness.","WAF, IDS/IPS, web/server logs","Source → target → URI/payload → response → process","Exploit signature; unusual POST; server process spawn; error spike","Patch, WAF/IPS controls, reduce exposure","Inspect server and process telemetry, preserve request evidence, scope successful execution","OWASP","CISA KEV"],
["Vulnerability Scan Detected","Scanner activity may be authorized or malicious reconnaissance.","Firewall, IDS, scanner logs","Source → targets → ports → timing → owner","Unknown source; external origin; sensitive targets; unusual schedule","Validate scanner allowlist and scope","If unauthorized, block/contain source and inspect targeted assets for exploitation","CISA KEV","NVD"]]],

["Incident Response & Forensics",[
["Endpoint Isolation Event","An endpoint has been isolated by security tooling or manually.","EDR, incident timeline","Host → user → alert → isolation time → preceding events","Isolation followed by repeated detections; multiple related hosts","Maintain containment until scope is understood","Preserve evidence, determine root cause, eradicate, validate before reconnecting","Defender XDR","CISA IR"],
["Credential Dumping Indicator","Telemetry suggests collection of credentials or credential material.","EDR, 4688, LSASS telemetry","Process → target → user → host → follow-on auth","Unexpected LSASS access; dump tools; privileged account use","Credential protections, EDR rules, least privilege","Isolate host, reset exposed credentials, invalidate sessions/tokens, hunt lateral movement","Sysinternals","ATT&CK"],
["Evidence Collection Required","An incident needs a repeatable evidence-preservation workflow.","EDR, SIEM, endpoint, cloud logs","Timeline → volatile data → files → logs → hashes","Logs missing; time skew; overwritten evidence; uncontrolled changes","Centralized logging, time sync, retention and chain-of-custody process","Preserve originals, document timestamps/actions, collect relevant volatile/nonvolatile evidence before cleanup","CISA IR","NIST 800-61"],
["Incident Closure Review","Before closure, verify containment, eradication, recovery and lessons learned.","SIEM, EDR, ticket/IR record","Root cause → scope → actions → validation → monitoring","Residual alerts; unresolved IOCs; incomplete root cause; missing evidence","Use closure checklist and post-incident review","Keep heightened monitoring, document gaps, update detections/playbooks and recovery actions","NIST 800-61","CISA IR"]]],

["Threat Intelligence & IOC",[
["Malicious IP Hit","An internal system communicated with an IP associated with suspicious intelligence.","Firewall, DNS, EDR, proxy","IP → host → process → domain → time → bytes","Repeated connections; C2-like timing; malicious reputation; suspicious process","Block based on confidence; enrich with multiple sources","Scope all hosts/users, isolate confirmed endpoint, collect process/network evidence","VirusTotal","AbuseIPDB"],
["Malicious Hash Hit","A file hash matches threat intelligence or a known malicious sample.","EDR, file events, malware intelligence","Hash → path → host → process → user → prevalence","Execution observed; multiple hosts; unsigned file; persistence","Quarantine/block hash; update detection","Isolate affected host(s), collect file/process timeline, hunt hash and related IOCs","VirusTotal","MalwareBazaar"],
["Malicious Domain Hit","DNS/proxy activity matches a malicious or suspicious domain.","DNS, proxy, EDR","Domain → users → hosts → URLs → process","Credential harvesting; newly registered domain; repeated beaconing","Block domain and related URLs; warn users","Reset credentials if submitted, isolate host if payload executed, scope all requests","URLScan","VirusTotal"],
["IOC Correlation Burst","Multiple IOCs from one incident cluster appear across the environment.","SIEM, EDR, DNS, firewall","IOC → hosts → users → time window → common infrastructure","Several related IOCs on one host; repeated across hosts; same process","Create temporary hunting/detection rule; contain high-confidence assets","Scope campaign, preserve evidence, block infrastructure and eradicate root cause","ATT&CK","ThreatFox"]]]
];

const esc=s=>s.replace(/[&<>"']/g,m=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[m]));
const KQL={"Suspicious Sign-in": "SigninLogs\n| where TimeGenerated > ago(24h)\n| summarize Attempts=count(), Successes=countif(ResultType == 0)\n    by UserPrincipalName, IPAddress, AppDisplayName, LocationDetails.countryOrRegion\n| order by Attempts desc", "Password Spray": "SigninLogs\n| where TimeGenerated > ago(24h)\n| where ResultType != 0\n| summarize Users=dcount(UserPrincipalName), Failures=count()\n    by IPAddress\n| where Users >= 5\n| order by Users desc", "Brute Force Login": "SigninLogs\n| where TimeGenerated > ago(24h)\n| where ResultType != 0\n| summarize Failures=count(), Users=dcount(UserPrincipalName)\n    by IPAddress, UserPrincipalName\n| order by Failures desc", "MFA Fatigue / Push Bombing": "SigninLogs\n| where TimeGenerated > ago(24h)\n| where ResultType != 0\n| summarize Attempts=count(), Countries=dcount(LocationDetails.countryOrRegion)\n    by UserPrincipalName, IPAddress, AppDisplayName\n| order by Attempts desc", "4624 — Successful Logon": "SecurityEvent\n| where TimeGenerated > ago(24h)\n| where EventID == 4624\n| summarize Logons=count() by Account, IpAddress, LogonType, Computer\n| order by Logons desc", "4625 — Failed Logon": "SecurityEvent\n| where TimeGenerated > ago(24h)\n| where EventID == 4625\n| summarize Failures=count() by Account, IpAddress, Computer\n| order by Failures desc", "4688 — Process Creation": "SecurityEvent\n| where TimeGenerated > ago(24h)\n| where EventID == 4688\n| project TimeGenerated, Computer, Account, NewProcessName, ParentProcessName, CommandLine\n| order by TimeGenerated desc", "4740 — Account Lockout": "SecurityEvent\n| where TimeGenerated > ago(24h)\n| where EventID == 4740\n| project TimeGenerated, Computer, TargetAccount, CallerComputerName\n| order by TimeGenerated desc", "7045 — New Service": "SecurityEvent\n| where TimeGenerated > ago(24h)\n| where EventID == 7045\n| project TimeGenerated, Computer, Account, ServiceName, ServiceFileName\n| order by TimeGenerated desc", "Kerberoasting": "SecurityEvent\n| where TimeGenerated > ago(24h)\n| where EventID == 4769\n| summarize Requests=count(), SPNs=dcount(ServiceName) by Account, IpAddress\n| order by Requests desc", "DCSync": "SecurityEvent\n| where TimeGenerated > ago(24h)\n| where EventID == 4662\n| where Properties has_any (\"Replicating Directory Changes\",\"Replicating Directory Changes All\")\n| project TimeGenerated, Computer, SubjectUserName, IpAddress, Properties\n| order by TimeGenerated desc", "Admin Group Membership Change": "SecurityEvent\n| where TimeGenerated > ago(24h)\n| where EventID in (4728, 4732, 4756)\n| project TimeGenerated, Computer, SubjectUserName, MemberName, TargetUserName, TargetDomainName\n| order by TimeGenerated desc", "RDP Anomaly": "SecurityEvent\n| where TimeGenerated > ago(24h)\n| where EventID == 4624\n| where LogonType == 10\n| summarize Sessions=count() by Account, IpAddress, Computer\n| order by Sessions desc", "SMB Lateral Movement": "SecurityEvent\n| where TimeGenerated > ago(24h)\n| where EventID in (5140, 5145)\n| summarize Events=count() by Account, IpAddress, Computer, ShareName\n| order by Events desc", "Scheduled Task Persistence": "SecurityEvent\n| where TimeGenerated > ago(24h)\n| where EventID == 4698\n| project TimeGenerated, Computer, SubjectUserName, TaskName, TaskContent\n| order by TimeGenerated desc", "Known Exploited Vulnerability": "DeviceTvmSoftwareVulnerabilities\n| where TimeGenerated > ago(24h)\n| where VulnerabilitySeverityLevel in (\"Critical\",\"High\")\n| summarize Assets=dcount(DeviceId) by CveId, VulnerabilitySeverityLevel\n| order by Assets desc", "Malicious IP Hit": "CommonSecurityLog\n| where TimeGenerated > ago(24h)\n| summarize Events=count(), Devices=dcount(DeviceName)\n    by SourceIP, DestinationIP, DeviceVendor, DeviceProduct\n| order by Events desc"};
function detail(a){
 const [n,meaning,logs,pivots,flags,prec,comp,tool1,tool2]=a;
 const links=[tool1,tool2].map(x=>`<a href="${R[x]||'#'}" target="_blank">${esc(x)}</a>`).join("");
 return `<div class="detail">
 <div class="row"><b>What the alert means</b>${esc(meaning)}</div>
 <div class="row"><b>What to check / Logs</b>${esc(logs)}</div>
 <div class="row"><b>Investigation pivots</b>${esc(pivots)}</div>
 <div class="row"><b class="flag">🚩 Red flags</b><span class="flag">${esc(flags)}</span></div>
 <div class="row"><b>Precaution / Preventive measures</b><span class="action">${esc(prec)}</span></div>
 <div class="row"><b>If compromise is suspected / confirmed</b><span class="action">${esc(comp)}</span></div><div class="row"><b>Query / KQL starting point</b><code class="query">${esc(KQL[n] || "Start from the named table/log source, filter the alert entity and time window, then summarize by user, host, source IP and outcome. Adapt field names to your tenant schema before production use.")}</code></div>
 <div class="row"><b>Evidence to collect</b>Alert ID/timestamps, affected user and host, source/destination, relevant raw logs, process/command line, file hash, screenshots or exports where appropriate, and the investigation timeline.</div>
 <div class="row"><b>Useful resources</b><div class="links">${links}</div></div>
 </div>`;
}
function render(){
 const q=(document.getElementById("search").value||"").toLowerCase(); let total=0;
 document.getElementById("toolkitGrid").innerHTML=data.map((c,i)=>{
   const alerts=c[1].filter(a=>a.join(" ").toLowerCase().includes(q)||c[0].toLowerCase().includes(q)); total+=alerts.length;
   if(!alerts.length)return "";
   return `<div class="category ${q?"open":""}"><button class="cat-head" onclick="this.parentElement.classList.toggle('open')"><span>${esc(c[0])}</span><small>${alerts.length} ALERTS ▾</small></button><div class="alerts">${alerts.map((a,j)=>`<div class="alert"><button onclick="this.parentElement.classList.toggle('active')"><span>${esc(a[0])}</span><span>+</span></button>${detail(a)}</div>`).join("")}</div></div>`;
 }).join("");
 document.getElementById("count").textContent=total+" investigation playbooks";
}
if(document.getElementById("search") && document.getElementById("toolkitGrid")){ document.getElementById("search").addEventListener("input",render); render(); }

const resourceCategories=[
["01 / MALWARE & URL ANALYSIS","Investigate suspicious files, URLs, domains and IPs using reputation, sandbox and malware-analysis resources.",[
["VirusTotal","File/hash/URL/IP/domain reputation, detections, related IOCs and community context.","Malware, phishing, suspicious files, URLs and IOC investigations.","https://www.virustotal.com/"],
["ANY.RUN","Interactive sandbox behavior including processes, commands, DNS, network connections and IOCs.","Malware samples, phishing attachments and suspicious executables.","https://any.run/"],
["Hybrid Analysis","Static/dynamic analysis, processes, network indicators, hashes and sandbox reports.","Malware analysis and suspicious file investigations.","https://www.hybrid-analysis.com/"],
["URLScan","URL behavior, redirects, requests, domains, IPs and screenshots.","Phishing URLs and suspicious web alerts.","https://urlscan.io/"],
["MalwareBazaar","Malware hashes, samples, tags and related intelligence.","Malware hash and sample investigations.","https://bazaar.abuse.ch/"],
["AbuseIPDB","IP abuse reports, confidence information and historical reports.","Brute force, scanning and suspicious source IP investigations.","https://www.abuseipdb.com/"]]],
["02 / SOC & DETECTION ENGINEERING","Resources for SIEM investigations, detection logic, ATT&CK mapping, query development and blue-team engineering.",[
["Microsoft Sentinel","Cloud-native SIEM, analytics, incidents, workbooks and investigation workflows.","SOC monitoring, KQL investigations and detection engineering.","https://azure.microsoft.com/products/microsoft-sentinel/"],
["Splunk","Search, correlation, dashboards and security content.","SIEM investigations, detection and threat hunting.","https://www.splunk.com/"],
["IBM QRadar","Offenses, events, flows and correlation context.","SOC offense investigation and correlation analysis.","https://www.ibm.com/products/qradar-siem"],
["Sigma","Open detection-rule format for sharing behavioral detections.","Detection engineering and SIEM rule development.","https://sigmahq.io/"],
["MITRE ATT&CK","Tactics, techniques, software and threat-actor mappings.","Alert investigation, hunting and detection coverage.","https://attack.mitre.org/"],
["ATT&CK Navigator","Visualize and compare ATT&CK techniques and coverage.","Threat-hunting planning and detection coverage reviews.","https://mitre-attack.github.io/attack-navigator/"]]],
["03 / DFIR & MALWARE RESEARCH","Tools for endpoint forensics, memory analysis, packet analysis and malware research.",[
["Volatility","Memory-forensics framework for extracting processes, handles and other artifacts.","Memory investigation and incident response.","https://volatilityfoundation.org/"],
["Autopsy","Digital-forensics platform for disk and filesystem investigation.","DFIR, timeline and artifact analysis.","https://www.autopsy.com/"],
["Wireshark","Packet capture inspection, protocols, endpoints and network conversations.","Network investigation, C2 and suspicious traffic analysis.","https://www.wireshark.org/"],
["CyberChef","Encoding, decoding, transformation and data-analysis utilities.","IOC handling, decoding and analyst data transformations.","https://gchq.github.io/CyberChef/"],
["REMnux","Linux toolkit and environment for reverse engineering and malware analysis.","Malware research and suspicious sample analysis.","https://remnux.org/"],
["FLARE-VM","Windows environment for reverse engineering and malware analysis.","Static/dynamic malware research.","https://github.com/mandiant/flare-vm"]]],
["04 / ANALYST UTILITIES","Fast enrichment and investigation utilities for IPs, domains, URLs, hashes and web artifacts.",[
["Shodan","Internet-exposed devices, ports, services and banners.","Asset exposure and reconnaissance investigations.","https://www.shodan.io/"],
["GreyNoise","Internet scanning activity and context around scanner IPs.","Port scanning and suspicious source-IP investigations.","https://www.greynoise.io/"],
["OWASP","Application-security guidance, testing knowledge and vulnerability references.","Web-security investigations and application-security research.","https://owasp.org/"],
["PortSwigger Web Security Academy","Interactive web-security labs and vulnerability learning resources.","Web attack investigation and validation.","https://portswigger.net/web-security"],
["Microsoft Sysinternals","Windows troubleshooting, process, system and security utilities.","Endpoint investigation and Windows analysis.","https://learn.microsoft.com/sysinternals/"],
["URLScan","Web request, redirect and page-level inspection.","Phishing and malicious-link investigations.","https://urlscan.io/"]]],
["05 / CLOUD & IDENTITY SECURITY","References for identity, endpoint, cloud and SaaS security investigations.",[
["Microsoft Entra","Identity, sign-in, audit, risk and access-control information.","Identity investigations, suspicious sign-ins and account compromise.","https://entra.microsoft.com/"],
["Microsoft Defender XDR","Unified incidents and security signals across Microsoft security products.","Endpoint, identity, email and cloud investigations.","https://security.microsoft.com/"],
["Microsoft Learn","Official Microsoft security, Azure, Entra and Sentinel documentation.","Product knowledge, configuration and investigation reference.","https://learn.microsoft.com/"],
["Okta","Identity and authentication platform documentation and security resources.","SSO, authentication and identity investigations.","https://www.okta.com/"],
["AWS Security","AWS security services, identity and cloud-security documentation.","Cloud investigations and IAM security.","https://aws.amazon.com/security/"],
["Google Cloud Security","Cloud security products, guidance and security research.","GCP security and cloud investigations.","https://cloud.google.com/security"]]],
["06 / LABS & PRACTICE","Hands-on environments for building SOC, blue-team, detection and web-security skills.",[
["TryHackMe","Guided cybersecurity rooms and practical exercises.","SOC, blue-team, detection and security fundamentals.","https://tryhackme.com/"],
["Hack The Box","Hands-on labs, machines and security challenges.","Offensive security, detection context and technical practice.","https://www.hackthebox.com/"],
["Blue Team Labs Online","Defensive security investigations and blue-team challenges.","SOC investigation, DFIR and threat hunting practice.","https://blueteamlabs.online/"],
["CyberDefenders","Blue-team and DFIR challenges based on investigation scenarios.","SOC, threat hunting and forensic practice.","https://cyberdefenders.org/"],
["PortSwigger Academy","Free interactive web-security labs.","Web attack analysis and application-security learning.","https://portswigger.net/web-security"],
["MITRE ATT&CK","Adversary behavior knowledge base for structured hunting practice.","Threat hunting and detection engineering exercises.","https://attack.mitre.org/"]]]
];

function resourceCard(r){return `<article class="resource-card"><div class="resource-top"><h3>${esc(r[0])}</h3><a class="resource-link" href="${r[3]}" target="_blank" rel="noopener noreferrer" aria-label="Open ${esc(r[0])}">↗ Open</a></div><ul><li><b>Check:</b> ${esc(r[1])}</li><li><b>Use for:</b> ${esc(r[2])}</li></ul></article>`;}
function renderResources(){document.getElementById("resourcesGrid").innerHTML=resourceCategories.map((c,i)=>`<div class="resource-category ${i===0?'open':''}"><button class="resource-cat-head" onclick="this.parentElement.classList.toggle('open')"><span><small>${esc(c[0])}</small><strong>${esc(c[0].replace(/^\d+ \/ /,''))}</strong></span><span class="resource-count">${c[2].length} RESOURCES ▾</span></button><div class="resource-desc">${esc(c[1])}</div><div class="resource-items">${c[2].map(resourceCard).join('')}</div></div>`).join('');}
if(document.getElementById("resourcesGrid")) renderResources();
if(document.getElementById("menu")) document.getElementById("menu").onclick=()=>document.body.classList.toggle("mobile");


/* ===== SAINSEC CYBEROPS CONSOLIDATED FINAL UI LAYER ===== */
const SAINSEC_KQL = {
"Suspicious Sign-in": `SigninLogs
| where TimeGenerated > ago(24h)
| summarize Attempts=count(), Successes=countif(ResultType == 0)
    by UserPrincipalName, IPAddress, AppDisplayName, LocationDetails.countryOrRegion
| order by Attempts desc`,
"Password Spray": `SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType != 0
| summarize Users=dcount(UserPrincipalName), Failures=count() by IPAddress
| where Users >= 5
| order by Users desc`,
"Brute Force Login": `SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType != 0
| summarize Failures=count(), Sources=dcount(IPAddress) by UserPrincipalName
| order by Failures desc`,
"MFA Fatigue / Push Bombing": `SigninLogs
| where TimeGenerated > ago(24h)
| summarize Attempts=count(), IPs=dcount(IPAddress), Apps=dcount(AppDisplayName)
    by UserPrincipalName
| where Attempts >= 5
| order by Attempts desc`,
"4624 — Successful Logon": `SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4624
| summarize Logons=count() by Account, IpAddress, LogonType, Computer
| order by Logons desc`,
"4625 — Failed Logon": `SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4625
| summarize Failures=count() by Account, IpAddress, Computer
| order by Failures desc`,
"4688 — Process Creation": `SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4688
| project TimeGenerated, Computer, Account, NewProcessName, ParentProcessName, CommandLine
| order by TimeGenerated desc`,
"4740 — Account Lockout": `SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4740
| project TimeGenerated, Computer, TargetAccount, CallerComputerName
| order by TimeGenerated desc`,
"7045 — New Service": `SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 7045
| project TimeGenerated, Computer, Account, ServiceName, ServiceFileName
| order by TimeGenerated desc`,
"Kerberoasting": `SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4769
| summarize Requests=count(), SPNs=dcount(ServiceName) by Account, IpAddress
| order by Requests desc`,
"DCSync": `SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4662
| where Properties has_any ("Replicating Directory Changes","Replicating Directory Changes All")
| project TimeGenerated, Computer, SubjectUserName, IpAddress, Properties
| order by TimeGenerated desc`,
"Admin Group Membership Change": `SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID in (4728,4732,4756)
| project TimeGenerated, Computer, SubjectUserName, MemberName, TargetUserName
| order by TimeGenerated desc`,
"RDP Anomaly": `SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4624 and LogonType == 10
| summarize Sessions=count() by Account, IpAddress, Computer
| order by Sessions desc`,
"SMB Lateral Movement": `SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID in (5140,5145)
| summarize Events=count() by Account, IpAddress, Computer, ShareName
| order by Events desc`,
"Scheduled Task Persistence": `SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4698
| project TimeGenerated, Computer, SubjectUserName, TaskName, TaskContent
| order by TimeGenerated desc`,
"Malicious IP Hit": `CommonSecurityLog
| where TimeGenerated > ago(24h)
| summarize Events=count(), Devices=dcount(DeviceName)
    by SourceIP, DestinationIP
| order by Events desc`,
"Malicious Hash Hit": `DeviceFileEvents
| where Timestamp > ago(24h)
| summarize Hosts=dcount(DeviceName), Events=count() by SHA256, FileName
| order by Hosts desc`
};

const SAINSEC_TOOLS = {
identity:["Microsoft Sentinel","Microsoft Entra","Defender XDR"],
email:["Defender XDR","URLScan","VirusTotal","Message Header Analyzer"],
endpoint:["Defender XDR","Microsoft Sysinternals","VirusTotal","CrowdStrike"],
network:["Wireshark","Zeek","Suricata","Nmap","GreyNoise"],
cloud:["Azure Activity Log","Microsoft Entra","Microsoft Sentinel"],
dfir:["Autopsy","Volatility","Velociraptor","Eric Zimmerman Tools"],
threat:["VirusTotal","AbuseIPDB","GreyNoise","ThreatFox","URLScan"],
detection:["MITRE ATT&CK","Sigma","YARA","CyberChef"],
web:["Burp Suite","OWASP ZAP","PortSwigger Academy"],
vuln:["Nessus","Qualys","Nmap","CISA KEV"]
};

const SAINSEC_TOOL_URLS = {
"Microsoft Sentinel":"https://azure.microsoft.com/products/microsoft-sentinel/",
"Microsoft Entra":"https://entra.microsoft.com/",
"Defender XDR":"https://security.microsoft.com/",
"Microsoft Sysinternals":"https://learn.microsoft.com/sysinternals/",
"CrowdStrike":"https://www.crowdstrike.com/",
"VirusTotal":"https://www.virustotal.com/",
"AbuseIPDB":"https://www.abuseipdb.com/",
"GreyNoise":"https://www.greynoise.io/",
"ThreatFox":"https://threatfox.abuse.ch/",
"URLScan":"https://urlscan.io/",
"Wireshark":"https://www.wireshark.org/",
"Zeek":"https://zeek.org/",
"Suricata":"https://suricata.io/",
"Nmap":"https://nmap.org/",
"MITRE ATT&CK":"https://attack.mitre.org/",
"Sigma":"https://sigmahq.io/",
"YARA":"https://virustotal.github.io/yara/",
"CyberChef":"https://gchq.github.io/CyberChef/",
"Autopsy":"https://www.autopsy.com/",
"Volatility":"https://volatilityfoundation.org/",
"Velociraptor":"https://docs.velociraptor.app/",
"Nessus":"https://www.tenable.com/products/nessus",
"Qualys":"https://www.qualys.com/",
"Burp Suite":"https://portswigger.net/burp",
"OWASP ZAP":"https://www.zaproxy.org/",
"PortSwigger Academy":"https://portswigger.net/web-security",
"CISA KEV":"https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
};

function sainsecSeverity(name){
  if(/ransomware|DCSync|credential dumping|admin role|key vault|malware|compromise/i.test(name)) return "Critical";
  if(/password spray|brute force|phishing|MFA|Kerberoasting|lateral|RDP|SMB|PowerShell|malicious|persistence|exploit/i.test(name)) return "High";
  return "Medium";
}
function sainsecTools(name, text){
  const x=(name+" "+text).toLowerCase(), out=[];
  const add=a=>a.forEach(v=>{if(!out.includes(v))out.push(v)});
  if(/sign-in|password|mfa|account|admin|entra|identity|role/i.test(x)) add(SAINSEC_TOOLS.identity);
  if(/phish|email|mailbox|attachment/i.test(x)) add(SAINSEC_TOOLS.email);
  if(/malware|endpoint|process|powershell|windows|lsass|service|scheduled|registry/i.test(x)) add(SAINSEC_TOOLS.endpoint);
  if(/network|firewall|dns|rdp|smb|ssh|port|http|proxy/i.test(x)) add(SAINSEC_TOOLS.network);
  if(/azure|cloud|key vault|storage|nsg/i.test(x)) add(SAINSEC_TOOLS.cloud);
  if(/forensic|evidence|memory|incident/i.test(x)) add(SAINSEC_TOOLS.dfir);
  if(/ioc|ip|hash|domain|threat/i.test(x)) add(SAINSEC_TOOLS.threat);
  if(/mitre|detection|hunt|kql|rule/i.test(x)) add(SAINSEC_TOOLS.detection);
  if(/web|url|http/i.test(x)) add(SAINSEC_TOOLS.web);
  if(/vulnerability|cve|scan/i.test(x)) add(SAINSEC_TOOLS.vuln);
  return out.slice(0,7);
}

function sainsecGenericKql(p){
  const n=p[0], text=p.join(" ");
  if(SAINSEC_KQL[n]) return SAINSEC_KQL[n];
  if(/password|sign-in|login|MFA|account/i.test(text))
    return `SigninLogs
| where TimeGenerated > ago(24h)
| summarize Events=count(), Users=dcount(UserPrincipalName), IPs=dcount(IPAddress)
    by UserPrincipalName, IPAddress
| order by Events desc`;
  if(/4624|4625|4688|4740|7045|Windows/i.test(text))
    return `SecurityEvent
| where TimeGenerated > ago(24h)
| project TimeGenerated, Computer, Account, EventID, IpAddress, CommandLine
| order by TimeGenerated desc`;
  if(/network|firewall|DNS|SMB|RDP|port|HTTP|proxy/i.test(text))
    return `CommonSecurityLog
| where TimeGenerated > ago(24h)
| summarize Events=count() by SourceIP, DestinationIP, DestinationPort, DeviceProduct
| order by Events desc`;
  if(/malware|endpoint|process|PowerShell|service|scheduled/i.test(text))
    return `DeviceProcessEvents
| where Timestamp > ago(24h)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc`;
  return `// Investigation starting point
// Filter the relevant table by alert entity + time window.
// Then pivot by user, host, source IP, process and outcome.
`;
}

function sainsecCopy(text, btn){
  if(navigator.clipboard) navigator.clipboard.writeText(text).then(()=>{
    const old=btn.textContent; btn.textContent="Copied"; setTimeout(()=>btn.textContent=old,1000);
  });
}

function sainsecRender(){
  const search=(document.getElementById("search")?.value||"").toLowerCase().trim();
  const severity=document.getElementById("severity")?.value||"all";
  let flat=[];
  data.forEach(cat=>cat[1].forEach(a=>flat.push({cat:cat[0],a})));
  flat=flat.filter(x=>{
    const text=x.cat+" "+x.a.join(" ");
    return (!search||text.toLowerCase().includes(search)) &&
      (severity==="all"||sainsecSeverity(x.a[0]).toLowerCase()===severity);
  });
  document.getElementById("count").textContent=flat.length+" playbooks";

  const groups={};
  flat.forEach(x=>{(groups[x.cat]??=[]).push(x.a)});
  document.getElementById("toolkitGrid").innerHTML=Object.entries(groups).map(([cat,items])=>`
    <div class="category ${search||severity!=="all"?"open":""}">
      <button class="cat-head" onclick="this.parentElement.classList.toggle('open')">
        <span>${esc(cat)}</span><small>${items.length} PLAYBOOKS ▾</small>
      </button>
      <div class="alerts">${items.map((p)=>{
        const sev=sainsecSeverity(p[0]), tools=sainsecTools(p[0],p.join(" "));
        const q=sainsecGenericKql(p);
        const links=tools.filter(t=>SAINSEC_TOOL_URLS[t]).map(t=>`<a href="${SAINSEC_TOOL_URLS[t]}" target="_blank" rel="noopener">${esc(t)}</a>`).join("");
        const idx=data.flatMap(c=>c[1]).indexOf(p);
        return `<div class="alert" data-severity="${sev.toLowerCase()}">
          <button onclick="this.parentElement.classList.toggle('active')">
            <span class="lefttitle"><span>${esc(p[0])}</span><span class="sev sev-${sev.toLowerCase()}">${sev}</span></span><span>+</span>
          </button>
          <div class="detail">
            <div class="row"><b>What the alert means</b>${esc(p[1])}</div>
            <div class="row"><b>Logs / Telemetry</b>${esc(p[2])}</div>
            <div class="row"><b>Investigation pivots</b>${esc(p[3])}</div>
            <div class="row"><b class="flag">🚩 Red flags</b><span class="flag">${esc(p[4])}</span></div>
            <div class="row"><b>🛡️ Precaution / Prevention</b><span class="action">${esc(p[5])}</span></div>
            <div class="row"><b>🔴 If compromise is suspected / confirmed</b><span class="action">${esc(p[6])}</span></div>
            <div class="row"><b>📋 Evidence to collect</b>Alert ID/timestamps, affected user and host, source/destination, raw logs, process/command line, file hash where relevant, screenshots/exports where appropriate, and the investigation timeline.</div>
            <div class="row"><b>MITRE ATT&CK</b><span class="tag">Map the observed behavior to the relevant ATT&CK technique before closing the investigation.</span></div>
            <div class="row"><b>🧰 Main tools</b><div class="toolchips">${tools.map(t=>`<span>${esc(t)}</span>`).join("")}</div></div>
            <div class="row"><b>🔎 KQL / Query starting point</b><code class="query">${esc(q)}</code><div class="copyrow"><button class="copy-kql" onclick="sainsecCopy(${JSON.stringify(q)},this)">Copy KQL</button></div><small class="query-note">Starting point only — validate connector coverage, table names, field names and time window in your Sentinel workspace.</small></div>
            <div class="row"><b>🔗 Official / reference links</b><div class="links">${links}</div></div>
          </div>
        </div>`;
      }).join("")}</div>
    </div>`).join("");
}

if(document.getElementById("toolkitGrid") && !document.getElementById("severity")){
  const bar=document.querySelector(".toolbar");
  if(bar){
    const input=document.getElementById("search");
    const sel=document.createElement("select"); sel.id="severity";
    sel.innerHTML='<option value="all">All severity</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option>';
    bar.insertBefore(sel, document.getElementById("count"));
    input?.addEventListener("input",sainsecRender);
    sel.addEventListener("change",sainsecRender);
  }
}
if(document.getElementById("toolkitGrid")) sainsecRender();
/* ===== END CONSOLIDATED FINAL UI LAYER ===== */
