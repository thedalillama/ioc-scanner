# IOC Packs

These IOC files are formatted for:

```powershell
powershell -ExecutionPolicy Bypass -File .\invoke-host-ioc.ps1 -Mode IOC -IocPath <file>
```

## Supported keys

The current `IOC` mode understands these keys:

- `Hashes`
- `Paths`
- `ServiceNames`
- `TaskNames`
- `RegistryPaths`
- `CommandLinePatterns`
- `FileNames`

## Included packs

### Windows endpoint-focused packs

These are the better starting point for this machine, which is running `Windows 10 Enterprise LTSC 2021 (build 19044)`.

### `microsoft-gentlemen-ransomware-2026.json`

Source:

- Microsoft Security Blog, "The Gentlemen ransomware: Dissecting a self-propagating Go encryptor"  
  https://www.microsoft.com/en-us/security/blog/2026/05/28/the-gentlemen-ransomware-dissecting-a-self-propagating-go-encryptor/

Included from that source:

- scheduled task names used for persistence and propagation
- service names used for remote execution
- registry Run persistence values
- ransom note and temporary file names
- a small set of command-line hunting patterns called out in the analysis

### `microsoft-nobelium-sibot-goldmax-2021.json`

Source:

- Microsoft Security Blog, "GoldMax, GoldFinder, and Sibot: Analyzing NOBELIUM's layered persistence"  
  https://www.microsoft.com/en-us/security/blog/2021/03/04/goldmax-goldfinder-sibot-analyzing-nobelium-malware/

Included from that source:

- GoldMax, GoldFinder, and Sibot SHA-256 hashes
- Sibot scheduled task name
- Sibot registry persistence path
- task file path used by one Sibot variant

### `cisa-play-ransomware-2025.json`

Source:

- CISA, "#StopRansomware: Play Ransomware"  
  https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-352a

Included from that source:

- hashes from CISA's updated IOC table
- associated Windows payload and tool file names mentioned alongside those hashes

Notes:

- `microsoft-gentlemen-ransomware-2026.json` contains some broad command-line patterns and is best used as a hunting pack, not as a high-confidence single-hit compromise verdict.
- `microsoft-nobelium-sibot-goldmax-2021.json` and `cisa-play-ransomware-2025.json` are more specific and lower-noise for this host.

### `microsoft-hafnium-exchange-2021.json`

Source:

- Microsoft Security Blog, "HAFNIUM targeting Exchange Servers"  
  https://www.microsoft.com/en-us/security/blog/2021/03/02/hafnium-targeting-exchange-servers/

Included from that source:

- web shell SHA-256 hashes
- suspicious Exchange-related paths
- known web shell file names
- command-line patterns Microsoft explicitly called out for hunting

### `unit42-manageengine-kdcsponge-nglite-2020.json`

Source:

- Palo Alto Networks Unit 42, "KdcSponge, NGLite, Godzilla Webshell Used in Targeted Attack Campaign"  
  https://unit42.paloaltonetworks.com/manageengine-godzilla-nglite-kdcsponge/

Included from that source:

- SHA-256 hashes for dropper, NGLite, Godzilla webshell, and KdcSponge samples
- registry Run/RunOnce persistence indicators
- file names derived from the registry persistence examples

### `cisa-mar-251132-sharepoint-2025.json`

Sources:

- CISA Malware Analysis Report snippet for `MAR-251132.c1.v1` surfaced in CISA search results  
  https://www.cisa.gov/sites/default/files/2025-08/MAR-251132.c1.v1.CLEAR_.pdf
- CISA alert landing page about the same MAR  
  https://www.cisa.gov/news-events/alerts/2025/08/06/cisa-releases-malware-analysis-report-associated-microsoft-sharepoint-vulnerabilities

Included from that source:

- a published SHA-256 from the MAR search snippet

## Notes

- These packs are intended to validate and demonstrate the IOC workflow against reputable-source indicators.
- Some indicators are broad by design and may produce many matches.
- The current script does not yet natively match domains or IP addresses, so those were omitted even when the source published them.
