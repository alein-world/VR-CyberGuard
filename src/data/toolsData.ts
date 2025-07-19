export interface Tool {
  id: string;
  name: string;
  fullName: string;
  description: string;
  longDescription: string;
  category: string;
  difficulty: 'Beginner' | 'Intermediate' | 'Advanced';
  lastUpdated: string;
  officialSite: string;
  icon: string;
  whatItIs: string;
  whatItsUsedFor: string;
  howItWorks: string;
  commands: string[];
  results: string[];
  useCases: string[];
  features: string[];
  installSteps: string[];
  basicUsage: string[];
}

export const toolsData: Record<string, Tool[]> = {
  "information-gathering": [
    {
      id: "nmap",
      name: "Nmap",
      fullName: "Network Mapper",
      description: "Network discovery and security auditing utility",
      longDescription: "Nmap is used to discover hosts and services on a computer network by sending packets and analyzing the responses. It provides a number of features for probing computer networks, including host discovery and service and operating system detection.",
      category: "Information Gathering",
      difficulty: "Beginner",
      lastUpdated: "2024-01-15",
      officialSite: "https://nmap.org",
      icon: "🔍",
      whatItIs: "A powerful network scanning tool used for network discovery and security auditing.",
      whatItsUsedFor: "Network administrators and security professionals use Nmap to identify what devices are running on their systems, discovering hosts that are available and the services they offer, finding open ports, and detecting security risks.",
      howItWorks: "Nmap sends specially crafted packets to the target host(s) and then analyzes their responses. Based on the responses, it can determine what services are running, what operating system is running, what type of device it is, and many other characteristics.",
      commands: [
        "nmap -sn 192.168.1.0/24",
        "nmap -A target.com",
        "nmap -sS -O target.com",
        "nmap -p- --open target.com"
      ],
      results: [
        "Host Discovery Complete: Found 12 active hosts",
        "Port Scan Complete: Open ports - 22, 80, 443, 8080",
        "OS Detection: Linux 3.2 - 4.9 (98% confidence)",
        "All ports scan: 65535 ports scanned, 4 open"
      ],
      useCases: [
        "Network inventory and asset management",
        "Monitoring host or service uptime",
        "Network security auditing",
        "Firewall testing and configuration"
      ],
      features: [
        "Host discovery",
        "Port scanning",
        "OS detection",
        "Service version detection",
        "Scriptable interaction with target"
      ],
      installSteps: [
        "Download from official website: nmap.org",
        "Install using package manager: sudo apt install nmap",
        "Verify installation: nmap --version",
        "Run first scan: nmap localhost"
      ],
      basicUsage: [
        "Basic ping scan: nmap -sn [target]",
        "TCP SYN scan: nmap -sS [target]",
        "Aggressive scan: nmap -A [target]",
        "Scan specific ports: nmap -p 80,443 [target]"
      ]
    },
    {
      id: "masscan",
      name: "Masscan",
      fullName: "Mass IP Port Scanner",
      description: "High-speed TCP port scanner capable of scanning the entire internet",
      longDescription: "Masscan is an Internet-scale port scanner. It can scan the entire Internet in under 6 minutes, transmitting 10 million packets per second, from a single machine.",
      category: "Information Gathering",
      difficulty: "Intermediate",
      lastUpdated: "2024-01-10",
      officialSite: "https://github.com/robertdavidgraham/masscan",
      icon: "⚡",
      whatItIs: "An extremely fast port scanner designed for scanning large networks quickly.",
      whatItsUsedFor: "Used by penetration testers and security researchers to quickly identify open ports across large IP ranges, making it ideal for initial network reconnaissance.",
      howItWorks: "Uses its own TCP/IP stack to send SYN packets asynchronously, allowing it to scan at extremely high speeds without being limited by the operating system's network stack.",
      commands: [
        "masscan -p80,8080 10.0.0.0/8",
        "masscan -p1-65535 192.168.1.0/24 --rate=1000",
        "masscan -p80 0.0.0.0/0 --rate=10000",
        "masscan --top-ports 100 192.168.1.0/24"
      ],
      results: [
        "Discovered open port 80/tcp on 192.168.1.1",
        "Discovered open port 443/tcp on 192.168.1.5",
        "Discovered open port 22/tcp on 192.168.1.10",
        "Rate: 1000.00 packets/sec"
      ],
      useCases: [
        "Large-scale network reconnaissance",
        "Internet-wide port scanning",
        "Quick network asset discovery",
        "Security research and monitoring"
      ],
      features: [
        "Extremely high-speed scanning",
        "Custom TCP/IP stack",
        "Asynchronous transmission",
        "Banner grabbing capabilities",
        "Output in multiple formats"
      ],
      installSteps: [
        "Clone from GitHub: git clone https://github.com/robertdavidgraham/masscan",
        "Install dependencies: sudo apt install build-essential",
        "Compile: make",
        "Install: sudo make install"
      ],
      basicUsage: [
        "Basic scan: masscan -p80 192.168.1.0/24",
        "Multiple ports: masscan -p80,443,22 [target]",
        "Rate limiting: masscan -p80 [target] --rate=100",
        "Save results: masscan -p80 [target] -oX output.xml"
      ]
    },
    {
      id: "recon-ng",
      name: "Recon-ng",
      fullName: "Reconnaissance Framework",
      description: "Web reconnaissance framework with independent modules and database interaction",
      longDescription: "Recon-ng is a full-featured reconnaissance framework designed with the goal of providing a powerful environment to conduct open source web-based reconnaissance quickly and thoroughly.",
      category: "Information Gathering",
      difficulty: "Advanced",
      lastUpdated: "2024-01-12",
      officialSite: "https://github.com/lanmaster53/recon-ng",
      icon: "🌐",
      whatItIs: "A comprehensive OSINT framework for web-based reconnaissance.",
      whatItsUsedFor: "Security professionals use Recon-ng to gather information about targets through various online sources, social media, and public databases for penetration testing and security assessments.",
      howItWorks: "Uses modular architecture with independent modules that can be chained together to gather comprehensive intelligence about targets from multiple online sources.",
      commands: [
        "recon-ng",
        "marketplace install all",
        "modules load recon/domains-hosts/hackertarget",
        "info"
      ],
      results: [
        "Recon-ng Framework loaded successfully",
        "47 modules installed from marketplace",
        "Module loaded: recon/domains-hosts/hackertarget",
        "Found 15 subdomains for target domain"
      ],
      useCases: [
        "Domain and subdomain enumeration",
        "Social media intelligence gathering",
        "Email address harvesting",
        "Company information research"
      ],
      features: [
        "Modular framework architecture",
        "Database integration",
        "API key management",
        "Custom module development",
        "Report generation"
      ],
      installSteps: [
        "Install Python 3: sudo apt install python3-pip",
        "Clone repository: git clone https://github.com/lanmaster53/recon-ng.git",
        "Install requirements: pip3 install -r requirements.txt",
        "Run framework: python3 recon-ng"
      ],
      basicUsage: [
        "Start framework: recon-ng",
        "Install modules: marketplace install all",
        "Load module: modules load [module_name]",
        "Run module: run"
      ]
    },
    {
      id: "theharvester",
      name: "theHarvester",
      fullName: "E-mail, Subdomain and People Names Harvester",
      description: "Tool for gathering e-mail accounts, subdomain names, virtual hosts, open ports and banners",
      longDescription: "theHarvester is a very simple to use, yet powerful and effective tool designed to be used in the early stages of a penetration test or red team engagement.",
      category: "Information Gathering",
      difficulty: "Beginner",
      lastUpdated: "2024-01-08",
      officialSite: "https://github.com/laramies/theHarvester",
      icon: "📧",
      whatItIs: "An OSINT tool that gathers emails, subdomains, hosts, employee names, open ports and banners from different public sources.",
      whatItsUsedFor: "Used in the reconnaissance phase of penetration testing to gather information about a target organization from public sources like search engines, PGP key servers, and social networks.",
      howItWorks: "Queries various search engines and public databases to collect information associated with a target domain, including email addresses, subdomains, and employee information.",
      commands: [
        "theharvester -d example.com -l 500 -b google",
        "theharvester -d example.com -b all",
        "theharvester -d example.com -b linkedin",
        "theharvester -d example.com -l 200 -b shodan"
      ],
      results: [
        "Found 25 email addresses for example.com",
        "Discovered 12 subdomains",
        "Located 8 employee profiles on LinkedIn",
        "Identified 3 open ports via Shodan"
      ],
      useCases: [
        "Email address enumeration",
        "Subdomain discovery",
        "Employee information gathering",
        "Social media reconnaissance"
      ],
      features: [
        "Multiple search engine support",
        "Social media integration",
        "Subdomain enumeration",
        "Email harvesting",
        "Export to various formats"
      ],
      installSteps: [
        "Install Python 3: sudo apt install python3-pip",
        "Clone repository: git clone https://github.com/laramies/theHarvester.git",
        "Install requirements: pip3 install -r requirements.txt",
        "Run tool: python3 theHarvester.py"
      ],
      basicUsage: [
        "Basic harvest: theharvester -d [domain] -b google",
        "All sources: theharvester -d [domain] -b all",
        "Limit results: theharvester -d [domain] -l 100 -b google",
        "Save output: theharvester -d [domain] -b google -f output.html"
      ]
    },
    {
      id: "maltego",
      name: "Maltego",
      fullName: "Maltego Community Edition",
      description: "Interactive data mining tool for link analysis and intelligence gathering",
      longDescription: "Maltego is an interactive data mining tool that renders directed graphs for link analysis. The tool is used in online investigations for finding relationships between pieces of information from various sources located on the Internet.",
      category: "Information Gathering",
      difficulty: "Intermediate",
      lastUpdated: "2024-01-20",
      officialSite: "https://www.maltego.com",
      icon: "🕸️",
      whatItIs: "A visual link analysis tool that helps investigators see relationships between entities.",
      whatItsUsedFor: "Used by investigators, security professionals, and researchers to visualize and understand complex relationships between people, companies, websites, and other entities.",
      howItWorks: "Uses transforms to query various data sources and create visual graphs showing relationships between entities, making complex data easier to understand and analyze.",
      commands: [
        "Run Maltego GUI application",
        "Create new graph",
        "Add entity (Person/Company/Domain)",
        "Run transforms on selected entities"
      ],
      results: [
        "Generated link analysis graph with 50 entities",
        "Discovered 12 related companies",
        "Found social media connections",
        "Identified shared infrastructure"
      ],
      useCases: [
        "Link analysis and relationship mapping",
        "Digital forensics investigations",
        "Fraud investigations",
        "Cyber threat intelligence"
      ],
      features: [
        "Visual graph interface",
        "Real-time data transforms",
        "Collaboration capabilities",
        "Custom entity creation",
        "Export functionality"
      ],
      installSteps: [
        "Download from official website",
        "Create free account",
        "Install application package",
        "Launch and authenticate"
      ],
      basicUsage: [
        "Create new graph",
        "Add person/company entity",
        "Right-click to run transforms",
        "Analyze resulting connections"
      ]
    },
    {
      id: "shodan",
      name: "Shodan",
      fullName: "Shodan Search Engine",
      description: "Search engine for Internet-connected devices and services",
      longDescription: "Shodan is a search engine that lets users find specific types of computers connected to the internet using a variety of filters. It has been called the 'Google for hackers' because it can be used to find vulnerable systems.",
      category: "Information Gathering",
      difficulty: "Beginner",
      lastUpdated: "2024-01-18",
      officialSite: "https://www.shodan.io",
      icon: "📡",
      whatItIs: "A search engine for finding Internet-connected devices and their exposed services.",
      whatItsUsedFor: "Security researchers and penetration testers use Shodan to identify exposed devices, services, and potential vulnerabilities across the internet.",
      howItWorks: "Continuously scans the entire IPv4 address space and indexes the banners and metadata from services it finds, making this information searchable through its web interface and API.",
      commands: [
        "shodan search apache",
        "shodan host 8.8.8.8",
        "shodan count country:US",
        "shodan download --limit 1000 webcam"
      ],
      results: [
        "Found 2,341,567 Apache servers",
        "Host 8.8.8.8 - Google DNS server details",
        "Found 45,123,891 hosts in United States",
        "Downloaded 1000 webcam results"
      ],
      useCases: [
        "Internet asset discovery",
        "Vulnerability research",
        "Network security monitoring",
        "IoT device identification"
      ],
      features: [
        "Global internet scanning",
        "Real-time search results",
        "Historical data access",
        "API integration",
        "Advanced filtering options"
      ],
      installSteps: [
        "Create account at shodan.io",
        "Install CLI: pip install shodan",
        "Initialize API key: shodan init [API_KEY]",
        "Test connection: shodan info"
      ],
      basicUsage: [
        "Web search: Use shodan.io interface",
        "CLI search: shodan search [query]",
        "Host lookup: shodan host [IP]",
        "Count results: shodan count [query]"
      ]
    },
    {
      id: "subfinder",
      name: "Subfinder",
      fullName: "Subdomain Discovery Tool",
      description: "Fast passive subdomain enumeration tool",
      longDescription: "Subfinder is a subdomain discovery tool that discovers valid subdomains for websites using passive online sources. It has a simple modular architecture and is optimized for speed.",
      category: "Information Gathering",
      difficulty: "Beginner",
      lastUpdated: "2024-01-05",
      officialSite: "https://github.com/projectdiscovery/subfinder",
      icon: "🔎",
      whatItIs: "A passive subdomain enumeration tool that uses multiple online sources.",
      whatItsUsedFor: "Used by security researchers and bug bounty hunters to discover subdomains of target domains for reconnaissance and attack surface mapping.",
      howItWorks: "Queries multiple passive sources like certificate transparency logs, search engines, and DNS databases to find subdomains without directly scanning the target.",
      commands: [
        "subfinder -d example.com",
        "subfinder -d example.com -silent",
        "subfinder -d example.com -o subdomains.txt",
        "subfinder -dL domains.txt -o results.txt"
      ],
      results: [
        "www.example.com",
        "mail.example.com",
        "blog.example.com",
        "api.example.com"
      ],
      useCases: [
        "Bug bounty reconnaissance",
        "Attack surface mapping",
        "Domain monitoring",
        "Security assessments"
      ],
      features: [
        "Fast passive enumeration",
        "Multiple data sources",
        "Rate limiting support",
        "Custom resolver support",
        "Output in multiple formats"
      ],
      installSteps: [
        "Download from GitHub releases",
        "Or install with Go: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "Configure API keys in config file",
        "Test: subfinder -version"
      ],
      basicUsage: [
        "Basic scan: subfinder -d [domain]",
        "Silent mode: subfinder -d [domain] -silent",
        "Save output: subfinder -d [domain] -o output.txt",
        "Multiple domains: subfinder -dL domains.txt"
      ]
    }
  ],

  "wireless-hacking": [
    {
      id: "aircrack-ng",
      name: "Aircrack-ng",
      fullName: "Aircrack-ng Suite",
      description: "Complete suite of tools to assess WiFi network security",
      longDescription: "Aircrack-ng is a complete suite of tools to assess WiFi network security. It focuses on different areas of WiFi security: monitoring, attacking, testing, and cracking.",
      category: "Wireless Hacking",
      difficulty: "Intermediate",
      lastUpdated: "2024-01-14",
      officialSite: "https://aircrack-ng.org",
      icon: "📡",
      whatItIs: "A comprehensive WiFi network security assessment toolkit.",
      whatItsUsedFor: "Security professionals use Aircrack-ng to test the security of wireless networks, identify vulnerabilities, and assess WiFi encryption strength.",
      howItWorks: "The suite captures and analyzes wireless traffic, performs attacks on WiFi networks, and attempts to crack encryption keys using various techniques including dictionary attacks and brute force.",
      commands: [
        "airodump-ng wlan0mon",
        "aircrack-ng capture.cap -w wordlist.txt",
        "aireplay-ng -0 5 -a [BSSID] wlan0mon",
        "airmon-ng start wlan0"
      ],
      results: [
        "Monitoring Mode Activated: Interface wlan0mon ready",
        "WPA Handshake Captured: 4-way handshake complete",
        "Key Found! Password: 'admin123' (took 2.3 minutes)",
        "Deauth attack successful: 5 packets sent"
      ],
      useCases: [
        "WiFi penetration testing",
        "Wireless security auditing",
        "Network troubleshooting",
        "Security awareness training"
      ],
      features: [
        "Packet capture and analysis",
        "WEP and WPA/WPA2 cracking",
        "Deauthentication attacks",
        "Fake access point creation",
        "Statistical analysis"
      ],
      installSteps: [
        "Install on Kali: sudo apt update && sudo apt install aircrack-ng",
        "Ubuntu/Debian: sudo apt install aircrack-ng",
        "Check wireless interface: iwconfig",
        "Enable monitor mode: airmon-ng start wlan0"
      ],
      basicUsage: [
        "Start monitor mode: airmon-ng start wlan0",
        "Scan networks: airodump-ng wlan0mon",
        "Capture handshake: airodump-ng -c [channel] --bssid [MAC] -w capture wlan0mon",
        "Crack password: aircrack-ng capture.cap -w wordlist.txt"
      ]
    },
    {
      id: "kismet",
      name: "Kismet",
      fullName: "Kismet Wireless Network Detector",
      description: "Wireless network detector, sniffer, and intrusion detection system",
      longDescription: "Kismet is a wireless network and device detector, sniffer, wardriving tool, and WIDS (wireless intrusion detection) framework.",
      category: "Wireless Hacking",
      difficulty: "Advanced",
      lastUpdated: "2024-01-11",
      officialSite: "https://www.kismetwireless.net",
      icon: "📊",
      whatItIs: "A passive wireless network detector and packet analyzer with intrusion detection capabilities.",
      whatItsUsedFor: "Used by security professionals for wireless network discovery, monitoring, and intrusion detection in enterprise environments.",
      howItWorks: "Passively monitors wireless traffic across multiple channels and protocols, detecting networks, devices, and potential security threats without transmitting any packets.",
      commands: [
        "kismet",
        "kismet_server --daemonize",
        "kismet_client",
        "kismet -c wlan0"
      ],
      results: [
        "Detected 15 wireless networks",
        "Found 23 wireless devices",
        "Identified potential rogue AP",
        "Logged 45,678 packets in 10 minutes"
      ],
      useCases: [
        "Wireless network monitoring",
        "Rogue access point detection",
        "Wardriving and site surveys",
        "Wireless intrusion detection"
      ],
      features: [
        "Passive network detection",
        "Multiple protocol support",
        "Real-time monitoring",
        "Plugin architecture",
        "Web-based interface"
      ],
      installSteps: [
        "Install dependencies: sudo apt install build-essential",
        "Download source from official site",
        "Compile: ./configure && make && sudo make install",
        "Configure: sudo kismet_server --first-time"
      ],
      basicUsage: [
        "Start server: kismet",
        "Web interface: http://localhost:2501",
        "Command line: kismet -c wlan0",
        "View logs: tail -f ~/.kismet/logs/"
      ]
    },
    {
      id: "wifite",
      name: "Wifite",
      fullName: "Wifite2 Automated Wireless Auditor",
      description: "Automated wireless auditor for WEP, WPA/WPS encrypted networks",
      longDescription: "Wifite is a tool to audit WEP or WPA encrypted wireless networks. It uses aircrack-ng, pyrit, reaver, tshark tools to perform and automate standard wireless auditing.",
      category: "Wireless Hacking",
      difficulty: "Beginner",
      lastUpdated: "2024-01-09",
      officialSite: "https://github.com/derv82/wifite2",
      icon: "🎯",
      whatItIs: "An automated wireless network auditing tool that simplifies WiFi penetration testing.",
      whatItsUsedFor: "Used by penetration testers and security auditors to quickly assess the security of multiple wireless networks without manual configuration.",
      howItWorks: "Automates the entire wireless auditing process by scanning for networks, capturing handshakes, and attempting to crack passwords using various attack methods.",
      commands: [
        "wifite",
        "wifite --wpa --dict /path/to/wordlist.txt",
        "wifite --wps --timeout 60",
        "wifite --5ghz --showb"
      ],
      results: [
        "Scanning for wireless networks...",
        "Found 8 WPA networks, 2 WEP networks",
        "Handshake captured for 'HomeWiFi'",
        "Password cracked: 'password123'"
      ],
      useCases: [
        "Automated wireless auditing",
        "Quick security assessments",
        "Educational demonstrations",
        "Penetration testing"
      ],
      features: [
        "Automated attack execution",
        "Multiple attack methods",
        "Progress tracking",
        "Custom wordlist support",
        "WPS attack capabilities"
      ],
      installSteps: [
        "Clone repository: git clone https://github.com/derv82/wifite2.git",
        "Install Python dependencies: sudo python setup.py install",
        "Install required tools: sudo apt install aircrack-ng reaver",
        "Run: sudo wifite"
      ],
      basicUsage: [
        "Basic scan: sudo wifite",
        "WPA only: sudo wifite --wpa",
        "Custom wordlist: sudo wifite --dict wordlist.txt",
        "Show nearby: sudo wifite --showb"
      ]
    },
    {
      id: "bettercap",
      name: "Bettercap",
      fullName: "Bettercap Network Attack Framework",
      description: "Powerful, modular network attack and monitoring framework",
      longDescription: "Bettercap is a powerful, easily extensible and portable framework written in Go which aims to offer to security researchers and reverse engineers an easy to use, all-in-one solution with all the features they might possibly need for performing reconnaissance and attacking WiFi networks, Bluetooth Low Energy devices, and more.",
      category: "Wireless Hacking",
      difficulty: "Advanced",
      lastUpdated: "2024-01-13",
      officialSite: "https://www.bettercap.org",
      icon: "🛡️",
      whatItIs: "A comprehensive network attack and monitoring framework with modular architecture.",
      whatItsUsedFor: "Used by security researchers for WiFi attacks, Bluetooth exploitation, network reconnaissance, and man-in-the-middle attacks.",
      howItWorks: "Provides a modular framework with various modules for different attack vectors, allowing researchers to chain different techniques together for comprehensive network testing.",
      commands: [
        "bettercap -iface wlan0",
        "wifi.recon on",
        "wifi.deauth [BSSID]",
        "ble.recon on"
      ],
      results: [
        "WiFi interface wlan0 monitor mode enabled",
        "Found 12 WiFi networks in range",
        "Deauth attack sent to target network",
        "BLE devices scan started"
      ],
      useCases: [
        "WiFi network attacks",
        "Bluetooth Low Energy exploitation",
        "Network reconnaissance",
        "Man-in-the-middle attacks"
      ],
      features: [
        "Modular architecture",
        "Web-based UI",
        "Real-time packet manipulation",
        "Custom scripts support",
        "Cross-platform compatibility"
      ],
      installSteps: [
        "Download from GitHub releases",
        "Install: sudo apt install bettercap",
        "Or compile from source with Go",
        "Test: bettercap -version"
      ],
      basicUsage: [
        "Start interactive: bettercap",
        "WiFi recon: wifi.recon on",
        "Show networks: wifi.show",
        "Web UI: ui.update && web.ui on"
      ]
    },
    {
      id: "wpscan",
      name: "WPScan",
      fullName: "WordPress Security Scanner",
      description: "WordPress vulnerability scanner and security testing tool",
      longDescription: "WPScan is a free, for non-commercial use, black box WordPress vulnerability scanner written for security professionals and blog maintainers to test the security of their WordPress websites.",
      category: "Web Application Assessment",
      difficulty: "Intermediate",
      lastUpdated: "2024-01-16",
      officialSite: "https://wpscan.com",
      icon: "🌐",
      whatItIs: "A specialized security scanner designed specifically for WordPress websites.",
      whatItsUsedFor: "Used by security professionals to identify vulnerabilities in WordPress installations, including plugin and theme vulnerabilities, weak passwords, and misconfigurations.",
      howItWorks: "Scans WordPress sites by checking for known vulnerabilities in core, plugins, and themes, performing user enumeration, and testing for common security issues.",
      commands: [
        "wpscan --url https://example.com",
        "wpscan --url https://example.com --enumerate p",
        "wpscan --url https://example.com --passwords passwords.txt",
        "wpscan --url https://example.com --enumerate u"
      ],
      results: [
        "WordPress version 5.8.1 identified",
        "Found 3 vulnerable plugins",
        "Enumerated 5 users",
        "Weak password found for admin user"
      ],
      useCases: [
        "WordPress security auditing",
        "Vulnerability assessment",
        "Penetration testing",
        "Compliance checking"
      ],
      features: [
        "WordPress core vulnerability detection",
        "Plugin and theme enumeration",
        "User enumeration",
        "Password brute forcing",
        "API token support"
      ],
      installSteps: [
        "Install Ruby: sudo apt install ruby-dev",
        "Install gem: gem install wpscan",
        "Update database: wpscan --update",
        "Test: wpscan --version"
      ],
      basicUsage: [
        "Basic scan: wpscan --url [URL]",
        "Enumerate plugins: wpscan --url [URL] --enumerate p",
        "User enum: wpscan --url [URL] --enumerate u",
        "Brute force: wpscan --url [URL] --passwords wordlist.txt"
      ]
    }
  ],

  "phishing-social-engineering": [
    {
      id: "set",
      name: "SET",
      fullName: "Social Engineer Toolkit",
      description: "Framework for social engineering attacks and phishing campaigns",
      longDescription: "The Social-Engineer Toolkit (SET) is specifically designed to perform advanced attacks against the human element. SET was written by David Kennedy (ReL1K) and with a lot of help from the community it has incorporated attacks never before seen in an exploitation toolset.",
      category: "Phishing & Social Engineering",
      difficulty: "Intermediate",
      lastUpdated: "2024-01-17",
      officialSite: "https://github.com/trustedsec/social-engineer-toolkit",
      icon: "🎭",
      whatItIs: "A comprehensive social engineering framework for testing human vulnerabilities.",
      whatItsUsedFor: "Used by penetration testers and security awareness trainers to simulate phishing attacks, test employee susceptibility to social engineering, and create realistic attack scenarios.",
      howItWorks: "Provides various attack vectors including spear-phishing, website cloning, infectious media generation, and SMS phishing to test human elements of security.",
      commands: [
        "setoolkit",
        "1) Social-Engineering Attacks",
        "2) Website Attack Vectors",
        "3) Credential Harvester Attack Method"
      ],
      results: [
        "SET Framework loaded successfully",
        "Cloned website created at /var/www/html",
        "Credential harvester listening on port 80",
        "Captured 5 credentials in 30 minutes"
      ],
      useCases: [
        "Phishing simulation campaigns",
        "Security awareness training",
        "Employee susceptibility testing",
        "Red team exercises"
      ],
      features: [
        "Website cloning",
        "Phishing email generation",
        "Credential harvesting",
        "Infectious media creation",
        "SMS phishing attacks"
      ],
      installSteps: [
        "Clone repository: git clone https://github.com/trustedsec/social-engineer-toolkit/",
        "Navigate to directory: cd social-engineer-toolkit",
        "Install: sudo python setup.py install",
        "Run: sudo setoolkit"
      ],
      basicUsage: [
        "Start SET: sudo setoolkit",
        "Select attack vector from menu",
        "Configure target parameters",
        "Launch attack and monitor results"
      ]
    },
    {
      id: "gophish",
      name: "Gophish",
      fullName: "Gophish Phishing Framework",
      description: "Open-source phishing toolkit designed for businesses and penetration testers",
      longDescription: "Gophish is an open-source phishing toolkit designed for businesses and penetration testers. It provides the ability to quickly and easily setup and execute phishing engagements and security awareness training.",
      category: "Phishing & Social Engineering",
      difficulty: "Beginner",
      lastUpdated: "2024-01-19",
      officialSite: "https://getgophish.com",
      icon: "🎣",
      whatItIs: "A user-friendly phishing framework with web-based management interface.",
      whatItsUsedFor: "Used by organizations and security teams to conduct phishing simulations, track employee responses, and provide security awareness training.",
      howItWorks: "Provides a web-based interface to create and manage phishing campaigns, track user interactions, and generate detailed reports on campaign effectiveness.",
      commands: [
        "./gophish",
        "Access web interface at https://localhost:3333",
        "Create campaign via web UI",
        "Monitor results in dashboard"
      ],
      results: [
        "Gophish server started on port 3333",
        "Campaign 'Q1 Training' launched to 100 users",
        "15 users clicked phishing link",
        "5 users submitted credentials"
      ],
      useCases: [
        "Corporate phishing training",
        "Security awareness programs",
        "Compliance testing",
        "Employee education"
      ],
      features: [
        "Web-based management",
        "Email template creation",
        "Landing page designer",
        "Real-time tracking",
        "Detailed reporting"
      ],
      installSteps: [
        "Download binary from GitHub releases",
        "Extract: unzip gophish-v0.x.x-linux-64bit.zip",
        "Make executable: chmod +x gophish",
        "Run: ./gophish"
      ],
      basicUsage: [
        "Start server: ./gophish",
        "Access web UI: https://localhost:3333",
        "Create email template",
        "Launch phishing campaign"
      ]
    },
    {
      id: "king-phisher",
      name: "King Phisher",
      fullName: "King Phisher Phishing Campaign Toolkit",
      description: "Tool for testing and promoting user awareness by simulating real world phishing attacks",
      longDescription: "King Phisher is a tool for testing and promoting user awareness by simulating real world phishing attacks. It features an easy to use, yet very flexible architecture allowing full control over both emails and server content.",
      category: "Phishing & Social Engineering",
      difficulty: "Advanced",
      lastUpdated: "2024-01-06",
      officialSite: "https://github.com/securestate/king-phisher",
      icon: "👑",
      whatItIs: "An advanced phishing campaign toolkit with powerful customization capabilities.",
      whatItsUsedFor: "Used by security professionals for sophisticated phishing simulations with detailed tracking and advanced evasion techniques.",
      howItWorks: "Combines email phishing with a customizable web server to create realistic phishing scenarios while providing detailed analytics and user tracking.",
      commands: [
        "king-phisher-server",
        "king-phisher-client",
        "Configure campaign parameters",
        "Launch phishing simulation"
      ],
      results: [
        "King Phisher server initialized",
        "Client connected successfully",
        "Campaign targeting 50 users launched",
        "Detailed analytics available in dashboard"
      ],
      useCases: [
        "Advanced phishing simulations",
        "Red team operations",
        "Security research",
        "Advanced awareness training"
      ],
      features: [
        "Advanced email templating",
        "Custom web server",
        "Detailed user tracking",
        "Plugin architecture",
        "Geographic targeting"
      ],
      installSteps: [
        "Install dependencies: sudo apt install python3-dev",
        "Clone repository: git clone https://github.com/securestate/king-phisher.git",
        "Install: sudo python3 setup.py install",
        "Configure server and run"
      ],
      basicUsage: [
        "Start server: king-phisher-server",
        "Launch client: king-phisher-client",
        "Create campaign template",
        "Monitor results in real-time"
      ]
    },
    {
      id: "evilginx",
      name: "Evilginx",
      fullName: "Evilginx2 Advanced Phishing Framework",
      description: "Man-in-the-middle attack framework for phishing login credentials and session cookies",
      longDescription: "Evilginx is a man-in-the-middle attack framework used for phishing login credentials along with session cookies, which in turn allows to bypass 2-factor authentication protection.",
      category: "Phishing & Social Engineering",
      difficulty: "Advanced",
      lastUpdated: "2024-01-21",
      officialSite: "https://github.com/kgretzky/evilginx2",
      icon: "👹",
      whatItIs: "An advanced MITM framework that can bypass 2FA by stealing session cookies.",
      whatItsUsedFor: "Used by red team operators and advanced penetration testers to demonstrate sophisticated phishing attacks that can bypass modern security measures.",
      howItWorks: "Acts as a reverse proxy between the target user and the legitimate website, capturing credentials and session cookies in real-time while maintaining the appearance of the legitimate site.",
      commands: [
        "evilginx2",
        "config domain example.com",
        "phishlets enable office365",
        "lures create office365"
      ],
      results: [
        "Evilginx2 framework started",
        "Domain configured: evil-example.com",
        "Office365 phishlet enabled",
        "Phishing lure created and ready"
      ],
      useCases: [
        "Advanced phishing demonstrations",
        "2FA bypass testing",
        "Red team operations",
        "Security research"
      ],
      features: [
        "Real-time credential capture",
        "Session cookie theft",
        "2FA bypass capabilities",
        "Multiple service phishlets",
        "Advanced evasion techniques"
      ],
      installSteps: [
        "Install Go: sudo apt install golang-go",
        "Clone repo: git clone https://github.com/kgretzky/evilginx2.git",
        "Build: make",
        "Configure domain and SSL certificates"
      ],
      basicUsage: [
        "Start: ./evilginx",
        "Configure domain: config domain [domain]",
        "Enable phishlet: phishlets enable [service]",
        "Create lure: lures create [service]"
      ]
    },
    {
      id: "beef",
      name: "BeEF",
      fullName: "Browser Exploitation Framework",
      description: "Web browser penetration testing framework",
      longDescription: "BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.",
      category: "Phishing & Social Engineering",
      difficulty: "Intermediate",
      lastUpdated: "2024-01-04",
      officialSite: "https://beefproject.com",
      icon: "🥩",
      whatItIs: "A browser exploitation framework that hooks web browsers for penetration testing.",
      whatItsUsedFor: "Used to demonstrate the impact of browser-based attacks and test client-side security by exploiting web browser vulnerabilities.",
      howItWorks: "Injects a JavaScript hook into target browsers, allowing the attacker to control the browser and execute various attack modules against the hooked browser.",
      commands: [
        "./beef",
        "Access web interface at http://localhost:3000/ui/panel",
        "Hook browser with JavaScript payload",
        "Execute modules on hooked browsers"
      ],
      results: [
        "BeEF server started on port 3000",
        "Browser hooked successfully",
        "5 attack modules available",
        "Keylogger deployed to target browser"
      ],
      useCases: [
        "Browser security testing",
        "Client-side penetration testing",
        "Social engineering campaigns",
        "Security awareness demonstrations"
      ],
      features: [
        "Browser hooking",
        "Real-time browser control",
        "Modular attack framework",
        "Web-based interface",
        "Cross-platform compatibility"
      ],
      installSteps: [
        "Install Ruby: sudo apt install ruby-dev",
        "Clone repository: git clone https://github.com/beefproject/beef.git",
        "Install gems: bundle install",
        "Start BeEF: ./beef"
      ],
      basicUsage: [
        "Start framework: ./beef",
        "Access UI: http://localhost:3000/ui/panel",
        "Hook browser with provided script",
        "Execute modules on hooked clients"
      ]
    }
  ],

  "exploitation": [
    {
      id: "metasploit",
      name: "Metasploit",
      fullName: "Metasploit Framework",
      description: "Advanced penetration testing framework with exploit development capabilities",
      longDescription: "The Metasploit Framework is a Ruby-based, modular penetration testing platform that enables you to write, test, and execute exploit code. The Metasploit Framework contains a suite of tools that you can use to test security vulnerabilities, enumerate networks, execute attacks, and evade detection.",
      category: "Exploitation",
      difficulty: "Advanced",
      lastUpdated: "2024-01-22",
      officialSite: "https://www.metasploit.com",
      icon: "🚀",
      whatItIs: "The world's most used penetration testing framework for exploit development and vulnerability validation.",
      whatItsUsedFor: "Used by penetration testers, security researchers, and red teams to test vulnerabilities, develop exploits, and validate security controls in controlled environments.",
      howItWorks: "Provides a modular framework with exploits, payloads, encoders, and post-exploitation modules that can be combined to create comprehensive attack scenarios.",
      commands: [
        "msfconsole",
        "search type:exploit platform:windows",
        "use exploit/windows/smb/ms17_010_eternalblue",
        "set RHOSTS 192.168.1.100"
      ],
      results: [
        "Metasploit Framework started",
        "Found 23 matching exploits",
        "EternalBlue exploit loaded",
        "Target host configured: 192.168.1.100"
      ],
      useCases: [
        "Penetration testing",
        "Vulnerability validation",
        "Exploit development",
        "Security research"
      ],
      features: [
        "Extensive exploit database",
        "Payload generation",
        "Post-exploitation modules",
        "Vulnerability scanning",
        "Report generation"
      ],
      installSteps: [
        "Download installer from official site",
        "Install: sudo ./metasploit-latest-linux-x64-installer.run",
        "Initialize database: msfdb init",
        "Start console: msfconsole"
      ],
      basicUsage: [
        "Start console: msfconsole",
        "Search exploits: search [term]",
        "Use exploit: use [exploit_path]",
        "Set options and run: exploit"
      ]
    },
    {
      id: "sqlmap",
      name: "SQLMap",
      fullName: "Automatic SQL Injection Tool",
      description: "Automatic SQL injection and database takeover tool",
      longDescription: "sqlmap is an open source penetration testing tool that automates the process of detecting and exploiting SQL injection flaws and taking over of database servers.",
      category: "Exploitation",
      difficulty: "Intermediate",
      lastUpdated: "2024-01-15",
      officialSite: "http://sqlmap.org",
      icon: "💉",
      whatItIs: "An automated tool for detecting and exploiting SQL injection vulnerabilities.",
      whatItsUsedFor: "Used by penetration testers and security researchers to identify SQL injection vulnerabilities in web applications and demonstrate their impact.",
      howItWorks: "Automatically tests web application parameters for SQL injection vulnerabilities using various techniques and payloads, then exploits found vulnerabilities to extract data.",
      commands: [
        "sqlmap -u 'http://target.com/page.php?id=1'",
        "sqlmap -u 'http://target.com/page.php?id=1' --dbs",
        "sqlmap -u 'http://target.com/page.php?id=1' -D database --tables",
        "sqlmap -u 'http://target.com/page.php?id=1' -D database -T users --dump"
      ],
      results: [
        "SQL injection vulnerability detected",
        "Available databases: webapp, mysql, information_schema",
        "Tables found: users, products, orders",
        "User data extracted: 150 records dumped"
      ],
      useCases: [
        "SQL injection testing",
        "Database enumeration",
        "Data extraction",
        "Security assessments"
      ],
      features: [
        "Automatic injection detection",
        "Multiple DBMS support",
        "Data extraction capabilities",
        "File system access",
        "Operating system takeover"
      ],
      installSteps: [
        "Clone repository: git clone https://github.com/sqlmapproject/sqlmap.git",
        "Navigate to directory: cd sqlmap",
        "Install Python dependencies: pip install -r requirements.txt",
        "Test: python sqlmap.py --version"
      ],
      basicUsage: [
        "Basic test: sqlmap -u '[URL]'",
        "List databases: sqlmap -u '[URL]' --dbs",
        "List tables: sqlmap -u '[URL]' -D [db] --tables",
        "Dump data: sqlmap -u '[URL]' -D [db] -T [table] --dump"
      ]
    },
    {
      id: "nuclei",
      name: "Nuclei",
      fullName: "Nuclei Vulnerability Scanner",
      description: "Fast vulnerability scanner with template-based scanning",
      longDescription: "Nuclei is a fast vulnerability scanner with template-based scanning that enables security researchers to create custom vulnerability detection templates with ease.",
      category: "Exploitation",
      difficulty: "Intermediate",
      lastUpdated: "2024-01-20",
      officialSite: "https://nuclei.projectdiscovery.io",
      icon: "⚛️",
      whatItIs: "A fast, template-based vulnerability scanner designed for large-scale scanning.",
      whatItsUsedFor: "Used by security teams for continuous security monitoring, bug bounty hunting, and automated vulnerability detection across large infrastructures.",
      howItWorks: "Uses YAML-based templates to define vulnerability checks, allowing for rapid scanning of web applications, networks, and cloud services.",
      commands: [
        "nuclei -u https://example.com",
        "nuclei -l targets.txt",
        "nuclei -u https://example.com -t cves/",
        "nuclei -u https://example.com -severity critical,high"
      ],
      results: [
        "Loaded 3,847 templates",
        "Found Apache version disclosure",
        "Detected SQL injection in /login.php",
        "Critical XSS vulnerability identified"
      ],
      useCases: [
        "Continuous security monitoring",
        "Bug bounty hunting",
        "Infrastructure scanning",
        "Compliance checking"
      ],
      features: [
        "Template-based scanning",
        "High-speed execution",
        "Community templates",
        "Custom template creation",
        "Multiple output formats"
      ],
      installSteps: [
        "Download from GitHub releases",
        "Or install with Go: go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest",
        "Update templates: nuclei -update-templates",
        "Test: nuclei -version"
      ],
      basicUsage: [
        "Basic scan: nuclei -u [URL]",
        "Multiple targets: nuclei -l targets.txt",
        "Specific templates: nuclei -u [URL] -t [template]",
        "Filter severity: nuclei -u [URL] -severity high"
      ]
    },
    {
      id: "burpsuite",
      name: "Burp Suite",
      fullName: "Burp Suite Professional",
      description: "Integrated platform for web application security testing",
      longDescription: "Burp Suite is an integrated platform for performing security testing of web applications. Its various tools work seamlessly together to support the entire testing process, from initial mapping and analysis of an application's attack surface, through to finding and exploiting security vulnerabilities.",
      category: "Exploitation",
      difficulty: "Intermediate",
      lastUpdated: "2024-01-18",
      officialSite: "https://portswigger.net/burp",
      icon: "🔥",
      whatItIs: "A comprehensive web application security testing platform with integrated tools.",
      whatItsUsedFor: "Used by web application security testers to identify vulnerabilities, manipulate HTTP traffic, and perform comprehensive security assessments.",
      howItWorks: "Acts as an intercepting proxy between the browser and web application, allowing security testers to analyze, modify, and replay HTTP requests and responses.",
      commands: [
        "Start Burp Suite application",
        "Configure browser proxy settings",
        "Intercept and modify HTTP requests",
        "Run automated scans"
      ],
      results: [
        "Burp Suite Professional started",
        "Proxy listening on 127.0.0.1:8080",
        "45 vulnerabilities found in scan",
        "SQL injection detected in parameter 'id'"
      ],
      useCases: [
        "Web application penetration testing",
        "API security testing",
        "Manual security testing",
        "Automated vulnerability scanning"
      ],
      features: [
        "Intercepting proxy",
        "Web vulnerability scanner",
        "Application spider",
        "Intruder tool for attacks",
        "Extensible platform"
      ],
      installSteps: [
        "Download from PortSwigger website",
        "Install Java Runtime Environment",
        "Run installer or JAR file",
        "Configure browser proxy settings"
      ],
      basicUsage: [
        "Start Burp Suite",
        "Configure proxy in browser",
        "Browse target application",
        "Analyze traffic in Burp"
      ]
    },
    {
      id: "cobalt-strike",
      name: "Cobalt Strike",
      fullName: "Cobalt Strike Adversary Simulation",
      description: "Commercial adversary simulation and red team operations platform",
      longDescription: "Cobalt Strike is a commercial penetration testing tool that provides a post-exploitation agent and covert channels to emulate a quiet long-term embedded actor in a customer network.",
      category: "Exploitation",
      difficulty: "Advanced",
      lastUpdated: "2024-01-10",
      officialSite: "https://www.cobaltstrike.com",
      icon: "⚔️",
      whatItIs: "A commercial red team operations and adversary simulation platform.",
      whatItsUsedFor: "Used by red teams and advanced penetration testers for post-exploitation activities, lateral movement, and simulating advanced persistent threats.",
      howItWorks: "Provides a framework for post-exploitation with advanced features for maintaining persistence, lateral movement, and covert communication channels.",
      commands: [
        "Start team server",
        "Connect Cobalt Strike client",
        "Generate payload beacons",
        "Execute post-exploitation modules"
      ],
      results: [
        "Team server started on port 50050",
        "Beacon established from target host",
        "Privilege escalation successful",
        "Lateral movement to 3 additional hosts"
      ],
      useCases: [
        "Red team operations",
        "Advanced penetration testing",
        "APT simulation",
        "Security training"
      ],
      features: [
        "Advanced payload generation",
        "Post-exploitation framework",
        "Covert communication",
        "Team collaboration",
        "Malleable C2 profiles"
      ],
      installSteps: [
        "Purchase license from official website",
        "Download team server and client",
        "Configure team server",
        "Connect clients to team server"
      ],
      basicUsage: [
        "Start team server with profile",
        "Connect client to team server",
        "Generate and deploy beacons",
        "Execute post-exploitation tasks"
      ]
    }
  ],

  "password-cracking": [
    {
      id: "hashcat",
      name: "Hashcat",
      fullName: "Advanced Password Recovery",
      description: "World's fastest password cracker and recovery utility",
      longDescription: "Hashcat is the world's fastest and most advanced password recovery utility, supporting five unique modes of attack for over 300 highly-optimized hashing algorithms.",
      category: "Password Cracking",
      difficulty: "Intermediate",
      lastUpdated: "2024-01-14",
      officialSite: "https://hashcat.net/hashcat/",
      icon: "🔓",
      whatItIs: "The fastest and most advanced password recovery tool available.",
      whatItsUsedFor: "Used by security professionals to test password strength, recover forgotten passwords, and assess authentication security in penetration tests.",
      howItWorks: "Utilizes GPU acceleration and optimized algorithms to perform various attack types including dictionary, brute-force, and rule-based attacks against password hashes.",
      commands: [
        "hashcat -m 0 hashes.txt wordlist.txt",
        "hashcat -m 1000 ntlm_hashes.txt rockyou.txt",
        "hashcat -m 22000 wpa_capture.hc22000 wordlist.txt",
        "hashcat -a 3 -m 0 hash.txt ?a?a?a?a?a?a"
      ],
      results: [
        "Cracking speed: 15.2 GH/s",
        "Password cracked: 'admin123'",
        "Session restored from checkpoint",
        "Hash type: MD5 detected automatically"
      ],
      useCases: [
        "Password security testing",
        "Digital forensics investigations",
        "Security audits",
        "Password recovery"
      ],
      features: [
        "GPU acceleration support",
        "300+ hash algorithm support",
        "Multiple attack modes",
        "Distributed cracking",
        "Real-time performance monitoring"
      ],
      installSteps: [
        "Download from official website",
        "Extract archive: tar -xzf hashcat-6.x.x.tar.gz",
        "Install OpenCL drivers for GPU",
        "Test: ./hashcat --version"
      ],
      basicUsage: [
        "Dictionary attack: hashcat -m [hash_type] [hash_file] [wordlist]",
        "Brute force: hashcat -a 3 -m [hash_type] [hash_file] [mask]",
        "Show cracked: hashcat --show [hash_file]",
        "Benchmark: hashcat -b"
      ]
    },
    {
      id: "john",
      name: "John the Ripper",
      fullName: "John the Ripper Password Cracker",
      description: "Fast password cracker with support for many hash types",
      longDescription: "John the Ripper is a fast password cracker, currently available for many flavors of Unix, macOS, Windows, DOS, BeOS, and OpenVMS. Its primary purpose is to detect weak Unix passwords.",
      category: "Password Cracking",
      difficulty: "Beginner",
      lastUpdated: "2024-01-12",
      officialSite: "https://www.openwall.com/john/",
      icon: "🗡️",
      whatItIs: "A classic and versatile password cracking tool with extensive hash format support.",
      whatItsUsedFor: "Used for password auditing, security testing, and recovering passwords from various hash formats in penetration testing scenarios.",
      howItWorks: "Employs multiple attack methods including dictionary attacks, incremental attacks, and external modes to crack passwords efficiently.",
      commands: [
        "john --wordlist=rockyou.txt hashes.txt",
        "john --incremental hashes.txt",
        "john --show hashes.txt",
        "john --format=NT ntlm_hashes.txt"
      ],
      results: [
        "Loaded 1500 password hashes",
        "Password cracked: user1:password123",
        "Session completed in 4m 32s",
        "Remaining 47 hashes uncracked"
      ],
      useCases: [
        "System password auditing",
        "Hash cracking challenges",
        "Security assessments",
        "Digital forensics"
      ],
      features: [
        "Multiple hash format support",
        "Incremental brute force",
        "Custom rules engine",
        "Distributed computing support",
        "Session management"
      ],
      installSteps: [
        "Install via package manager: sudo apt install john",
        "Or compile from source: make clean && make",
        "Download wordlists (rockyou, etc.)",
        "Test: john --test"
      ],
      basicUsage: [
        "Dictionary: john --wordlist=[wordlist] [hashfile]",
        "Incremental: john --incremental [hashfile]",
        "Show results: john --show [hashfile]",
        "Specific format: john --format=[type] [hashfile]"
      ]
    },
    {
      id: "hydra",
      name: "Hydra",
      fullName: "THC Hydra Password Cracker",
      description: "Fast network logon cracker supporting numerous protocols",
      longDescription: "Hydra is a parallelized login cracker which supports numerous protocols to attack. It is very fast and flexible, and new modules are easy to add.",
      category: "Password Cracking",
      difficulty: "Intermediate",
      lastUpdated: "2024-01-09",
      officialSite: "https://github.com/vanhauser-thc/thc-hydra",
      icon: "🐍",
      whatItIs: "A fast network authentication cracker that supports many different services.",
      whatItsUsedFor: "Used to test the strength of passwords on network services like SSH, FTP, HTTP, and many others during security assessments.",
      howItWorks: "Performs brute force and dictionary attacks against network authentication protocols by trying multiple username/password combinations in parallel.",
      commands: [
        "hydra -l admin -P passwords.txt ssh://192.168.1.100",
        "hydra -L users.txt -P passwords.txt ftp://target.com",
        "hydra -l admin -p admin http-get://target.com/admin",
        "hydra -C combo.txt ssh://192.168.1.100"
      ],
      results: [
        "Hydra v9.1 starting at 2024-01-15 10:30:25",
        "[SSH] host: 192.168.1.100 login: admin password: admin123",
        "1 of 1 target successfully completed",
        "Attack completed in 2m 15s"
      ],
      useCases: [
        "Network service authentication testing",
        "Web application login testing",
        "Remote service security auditing",
        "Password policy validation"
      ],
      features: [
        "50+ protocol support",
        "Parallel attack execution",
        "Flexible input options",
        "Resume capability",
        "Proxy support"
      ],
      installSteps: [
        "Install via package manager: sudo apt install hydra",
        "Or compile from source: ./configure && make && make install",
        "Verify installation: hydra -h",
        "Download wordlists for testing"
      ],
      basicUsage: [
        "SSH brute force: hydra -l [user] -P [passlist] ssh://[target]",
        "HTTP form: hydra -l [user] -P [passlist] [target] http-post-form",
        "FTP attack: hydra -L [userlist] -P [passlist] ftp://[target]",
        "Show help: hydra -h"
      ]
    },
    {
      id: "cewl",
      name: "CeWL",
      fullName: "Custom Word List Generator",
      description: "Custom wordlist generator that spiders websites",
      longDescription: "CeWL is a ruby app which spiders a given URL to a specified depth, optionally following external links, and returns a list of words which can then be used for password crackers such as John the Ripper.",
      category: "Password Cracking",
      difficulty: "Beginner",
      lastUpdated: "2024-01-07",
      officialSite: "https://github.com/digininja/CeWL",
      icon: "🕸️",
      whatItIs: "A custom wordlist generator that creates dictionaries from website content.",
      whatItsUsedFor: "Used to generate targeted wordlists for password attacks based on the target organization's website content and terminology.",
      howItWorks: "Crawls websites to extract words, which are then used to create custom dictionaries that are more likely to contain passwords used by the organization.",
      commands: [
        "cewl -d 2 -m 5 https://example.com",
        "cewl -w wordlist.txt https://example.com",
        "cewl -e --email_file emails.txt https://example.com",
        "cewl -a --meta_file meta.txt https://example.com"
      ],
      results: [
        "Found 247 words from target website",
        "Generated wordlist saved to wordlist.txt",
        "Extracted 12 email addresses",
        "Metadata analysis completed"
      ],
      useCases: [
        "Custom wordlist generation",
        "Targeted password attacks",
        "OSINT information gathering",
        "Social engineering preparation"
      ],
      features: [
        "Website crawling",
        "Custom word extraction",
        "Email address harvesting",
        "Metadata analysis",
        "Configurable depth and filtering"
      ],
      installSteps: [
        "Install Ruby: sudo apt install ruby",
        "Clone repository: git clone https://github.com/digininja/CeWL.git",
        "Install gems: gem install mini_exiftool spider nokogiri",
        "Make executable: chmod +x cewl.rb"
      ],
      basicUsage: [
        "Basic crawl: cewl [URL]",
        "Save wordlist: cewl -w output.txt [URL]",
        "Set depth: cewl -d [depth] [URL]",
        "Minimum word length: cewl -m [length] [URL]"
      ]
    },
    {
      id: "medusa",
      name: "Medusa",
      fullName: "Medusa Parallel Password Cracker",
      description: "Speedy, parallel, and modular login brute-forcer",
      longDescription: "Medusa is intended to be a speedy, massively parallel, modular, login brute-forcer. The goal is to support as many services which allow remote authentication as possible.",
      category: "Password Cracking",
      difficulty: "Intermediate",
      lastUpdated: "2024-01-11",
      officialSite: "http://foofus.net/goons/jmk/medusa/medusa.html",
      icon: "🐙",
      whatItIs: "A fast, parallel network authentication brute-forcing tool.",
      whatItsUsedFor: "Used for testing authentication security across multiple network services simultaneously with high-speed parallel processing.",
      howItWorks: "Performs massively parallel brute force attacks against network authentication services using modular design for different protocols.",
      commands: [
        "medusa -h 192.168.1.100 -u admin -P passwords.txt -M ssh",
        "medusa -H hosts.txt -U users.txt -P passwords.txt -M ftp",
        "medusa -h target.com -u admin -p admin -M http -m DIR:/admin",
        "medusa -h 192.168.1.0/24 -u admin -p admin -M ssh"
      ],
      results: [
        "Medusa v2.2 starting at 2024-01-15 14:20:35",
        "ACCOUNT FOUND: [ssh] Host: 192.168.1.100 User: admin Password: admin123",
        "Attack completed successfully",
        "1 valid account found in 3m 45s"
      ],
      useCases: [
        "Network authentication testing",
        "Large-scale password auditing",
        "Service security validation",
        "Penetration testing"
      ],
      features: [
        "Massively parallel execution",
        "Multiple protocol modules",
        "Flexible target specification",
        "Resume capability",
        "Detailed logging"
      ],
      installSteps: [
        "Install via package manager: sudo apt install medusa",
        "Or compile from source: ./configure && make && make install",
        "Check available modules: medusa -d",
        "Test installation: medusa -h"
      ],
      basicUsage: [
        "Single target: medusa -h [host] -u [user] -P [passlist] -M [module]",
        "Multiple hosts: medusa -H [hostlist] -u [user] -P [passlist] -M [module]",
        "User/pass combo: medusa -h [host] -C [combo_file] -M [module]",
        "List modules: medusa -d"
      ]
    }
  ],

  "vulnerability-scanning": [
    {
      id: "nessus",
      name: "Nessus",
      fullName: "Nessus Vulnerability Scanner",
      description: "Comprehensive vulnerability assessment scanner",
      longDescription: "Nessus is a proprietary vulnerability scanner developed by Tenable, Inc. It is free of charge for personal use in a non-enterprise environment.",
      category: "Vulnerability Scanning",
      difficulty: "Intermediate",
      lastUpdated: "2024-01-20",
      officialSite: "https://www.tenable.com/products/nessus",
      icon: "🛡️",
      whatItIs: "A comprehensive vulnerability scanner for identifying security weaknesses in networks and systems.",
      whatItsUsedFor: "Used by security professionals to identify vulnerabilities, misconfigurations, and compliance issues across enterprise networks and cloud environments.",
      howItWorks: "Performs authenticated and unauthenticated scans using a vast database of vulnerability checks to identify security issues and provide remediation guidance.",
      commands: [
        "Access web interface at https://localhost:8834",
        "Create new scan policy",
        "Configure target hosts and credentials",
        "Launch vulnerability scan"
      ],
      results: [
        "Scan completed: 25 hosts scanned",
        "Found 47 vulnerabilities (12 critical, 15 high)",
        "Generated compliance report",
        "Exported results to PDF/CSV"
      ],
      useCases: [
        "Enterprise vulnerability management",
        "Compliance auditing",
        "Risk assessment",
        "Security monitoring"
      ],
      features: [
        "Extensive vulnerability database",
        "Authenticated scanning",
        "Compliance templates",
        "Web-based interface",
        "Detailed reporting"
      ],
      installSteps: [
        "Download from Tenable website",
        "Install package: sudo dpkg -i Nessus-*.deb",
        "Start service: sudo systemctl start nessusd",
        "Access web UI: https://localhost:8834"
      ],
      basicUsage: [
        "Access web interface",
        "Create scan policy",
        "Add target hosts",
        "Review and export results"
      ]
    },
    {
      id: "openvas",
      name: "OpenVAS",
      fullName: "Open Vulnerability Assessment Scanner",
      description: "Open source vulnerability scanner and management solution",
      longDescription: "OpenVAS is a framework of several services and tools offering a comprehensive and powerful vulnerability scanning and vulnerability management solution.",
      category: "Vulnerability Scanning",
      difficulty: "Advanced",
      lastUpdated: "2024-01-18",
      officialSite: "https://openvas.org",
      icon: "🔍",
      whatItIs: "An open-source vulnerability scanner providing comprehensive security testing capabilities.",
      whatItsUsedFor: "Used for vulnerability assessment, security auditing, and compliance checking in enterprise environments as a cost-effective alternative to commercial scanners.",
      howItWorks: "Uses a collection of Network Vulnerability Tests (NVTs) to scan systems for known vulnerabilities and security issues, providing detailed reports and remediation advice.",
      commands: [
        "gvm-setup",
        "gvm-start",
        "gvm-check-setup",
        "Access web interface at https://localhost:9392"
      ],
      results: [
        "OpenVAS setup completed successfully",
        "Feed synchronization finished",
        "Scan completed: 15 vulnerabilities found",
        "Generated detailed security report"
      ],
      useCases: [
        "Network vulnerability assessment",
        "Security compliance auditing",
        "Continuous security monitoring",
        "Risk management"
      ],
      features: [
        "Comprehensive NVT feed",
        "Web-based management interface",
        "Automated scanning schedules",
        "Custom report generation",
        "Multi-user support"
      ],
      installSteps: [
        "Install via package manager or build from source",
        "Run setup: sudo gvm-setup",
        "Start services: sudo gvm-start",
        "Access web UI: https://localhost:9392"
      ],
      basicUsage: [
        "Setup: gvm-setup",
        "Start services: gvm-start",
        "Access web interface",
        "Create and run scans"
      ]
    },
    {
      id: "nikto",
      name: "Nikto",
      fullName: "Nikto Web Server Scanner",
      description: "Web server vulnerability scanner",
      longDescription: "Nikto is an Open Source web server scanner which performs comprehensive tests against web servers for multiple items, including over 6700 potentially dangerous files/programs.",
      category: "Vulnerability Scanning",
      difficulty: "Beginner",
      lastUpdated: "2024-01-16",
      officialSite: "https://cirt.net/Nikto2",
      icon: "🌐",
      whatItIs: "A web server vulnerability scanner that tests for dangerous files and configurations.",
      whatItsUsedFor: "Used by security professionals to identify web server vulnerabilities, dangerous files, outdated software, and configuration issues.",
      howItWorks: "Scans web servers by testing for thousands of known vulnerabilities, dangerous files, and configuration problems using comprehensive databases.",
      commands: [
        "nikto -h https://example.com",
        "nikto -h https://example.com -p 80,443,8080",
        "nikto -h https://example.com -o report.html",
        "nikto -h target_list.txt"
      ],
      results: [
        "Nikto v2.1.6 scan started",
        "Found /admin/ directory (potentially sensitive)",
        "Server leaks inodes via ETags",
        "Scan completed: 15 items found"
      ],
      useCases: [
        "Web application security testing",
        "Server configuration auditing",
        "Quick vulnerability assessment",
        "Penetration testing"
      ],
      features: [
        "6700+ vulnerability checks",
        "Multiple output formats",
        "Proxy support",
        "SSL support",
        "Plugin architecture"
      ],
      installSteps: [
        "Install via package manager: sudo apt install nikto",
        "Or clone from GitHub: git clone https://github.com/sullo/nikto.git",
        "Update database: nikto -update",
        "Test: nikto -Version"
      ],
      basicUsage: [
        "Basic scan: nikto -h [URL]",
        "Multiple ports: nikto -h [URL] -p [ports]",
        "Save output: nikto -h [URL] -o [file]",
        "SSL scan: nikto -h https://[target]"
      ]
    },
    {
      id: "nmap-scripts",
      name: "Nmap NSE",
      fullName: "Nmap Scripting Engine",
      description: "Powerful scripting engine for advanced network discovery and vulnerability detection",
      longDescription: "The Nmap Scripting Engine (NSE) allows users to write and share scripts that automate a wide variety of networking tasks. These scripts are executed in parallel with the speed and efficiency you expect from Nmap.",
      category: "Vulnerability Scanning",
      difficulty: "Intermediate",
      lastUpdated: "2024-01-14",
      officialSite: "https://nmap.org/nsedoc/",
      icon: "📜",
      whatItIs: "An advanced scripting framework for Nmap that enables automated vulnerability detection and network analysis.",
      whatItsUsedFor: "Used to extend Nmap's capabilities for vulnerability scanning, service enumeration, and advanced network reconnaissance.",
      howItWorks: "Executes Lua scripts against network targets to perform specific tests, vulnerability checks, and information gathering tasks.",
      commands: [
        "nmap --script vuln target.com",
        "nmap --script smb-vuln-* 192.168.1.0/24",
        "nmap --script http-enum target.com",
        "nmap --script ssl-cert,ssl-enum-ciphers target.com"
      ],
      results: [
        "NSE: Loaded 149 scripts for scanning",
        "Found CVE-2017-0144 (EternalBlue) vulnerability",
        "Discovered hidden directories: /admin, /backup",
        "SSL certificate expires in 30 days"
      ],
      useCases: [
        "Vulnerability assessment",
        "Service enumeration",
        "SSL/TLS testing",
        "Web application discovery"
      ],
      features: [
        "600+ pre-built scripts",
        "Custom script development",
        "Parallel execution",
        "Integration with Nmap",
        "Community contributions"
      ],
      installSteps: [
        "NSE comes with Nmap installation",
        "Update scripts: nmap --script-updatedb",
        "List scripts: nmap --script-help all",
        "Test: nmap --script-help vuln"
      ],
      basicUsage: [
        "Vulnerability scan: nmap --script vuln [target]",
        "Service enum: nmap --script [category] [target]",
        "Custom script: nmap --script [script_name] [target]",
        "Script help: nmap --script-help [script]"
      ]
    },
    {
      id: "lynis",
      name: "Lynis",
      fullName: "Lynis Security Auditing Tool",
      description: "Security auditing tool for Unix/Linux systems",
      longDescription: "Lynis is a security auditing tool for systems based on UNIX like Linux, macOS, BSD, and others. It performs an in-depth security scan and runs on the system itself.",
      category: "Vulnerability Scanning",
      difficulty: "Beginner",
      lastUpdated: "2024-01-13",
      officialSite: "https://cisofy.com/lynis/",
      icon: "🦁",
      whatItIs: "A comprehensive security auditing tool for Unix-like systems.",
      whatItsUsedFor: "Used by system administrators and security professionals to assess system security, identify misconfigurations, and improve security hardening.",
      howItWorks: "Performs hundreds of individual tests to determine the security posture of a system, checking configurations, installed software, and security controls.",
      commands: [
        "lynis audit system",
        "lynis show profiles",
        "lynis show groups",
        "lynis audit system --quick"
      ],
      results: [
        "Lynis 3.0.8 security audit started",
        "System hardening index: 72 (Good)",
        "Found 3 warnings, 12 suggestions",
        "Audit completed in 45 seconds"
      ],
      useCases: [
        "System security auditing",
        "Compliance checking",
        "Security hardening",
        "Configuration assessment"
      ],
      features: [
        "300+ security tests",
        "System hardening tips",
        "Compliance frameworks",
        "Detailed reporting",
        "Multi-platform support"
      ],
      installSteps: [
        "Download from official website",
        "Extract: tar xfz lynis-3.x.x.tar.gz",
        "Make executable: chmod +x lynis",
        "Run: ./lynis audit system"
      ],
      basicUsage: [
        "Full audit: lynis audit system",
        "Quick scan: lynis audit system --quick",
        "Show tests: lynis show tests",
        "View report: cat /var/log/lynis.log"
      ]
    }
  ],

  "forensics": [
    {
      id: "volatility",
      name: "Volatility",
      fullName: "Volatility Memory Forensics Framework",
      description: "Advanced memory forensics framework for incident response and malware analysis",
      longDescription: "The Volatility Framework is a completely open collection of tools, implemented in Python under the GNU General Public License, for the extraction of digital artifacts from volatile memory (RAM) samples.",
      category: "Forensics",
      difficulty: "Advanced",
      lastUpdated: "2024-01-19",
      officialSite: "https://www.volatilityfoundation.org",
      icon: "🧠",
      whatItIs: "A comprehensive framework for analyzing volatile memory dumps from compromised systems.",
      whatItsUsedFor: "Used by digital forensics investigators and incident responders to analyze memory dumps, detect malware, and reconstruct system activity.",
      howItWorks: "Analyzes raw memory dumps to extract processes, network connections, registry data, and other system artifacts that exist only in volatile memory.",
      commands: [
        "volatility -f memory.dmp imageinfo",
        "volatility -f memory.dmp --profile=Win7SP1x64 pslist",
        "volatility -f memory.dmp --profile=Win7SP1x64 netscan",
        "volatility -f memory.dmp --profile=Win7SP1x64 malfind"
      ],
      results: [
        "Suggested Profile(s): Win7SP1x64, Win7SP0x64",
        "Found 47 active processes",
        "Detected 12 network connections",
        "Malware injection detected in process 1337"
      ],
      useCases: [
        "Malware analysis",
        "Incident response",
        "Digital forensics investigations",
        "Memory analysis training"
      ],
      features: [
        "Cross-platform memory analysis",
        "Extensive plugin library",
        "Malware detection capabilities",
        "Timeline analysis",
        "Custom plugin development"
      ],
      installSteps: [
        "Install Python 2.7 (for Volatility 2) or Python 3 (for Volatility 3)",
        "Clone repository: git clone https://github.com/volatilityfoundation/volatility.git",
        "Install dependencies: pip install -r requirements.txt",
        "Test: python vol.py --info"
      ],
      basicUsage: [
        "Image info: volatility -f [dump] imageinfo",
        "Process list: volatility -f [dump] --profile=[profile] pslist",
        "Network scan: volatility -f [dump] --profile=[profile] netscan",
        "Malware find: volatility -f [dump] --profile=[profile] malfind"
      ]
    },
    {
      id: "autopsy",
      name: "Autopsy",
      fullName: "Autopsy Digital Forensics Platform",
      description: "Digital forensics platform with graphical interface",
      longDescription: "Autopsy is a digital forensics platform and graphical interface to The Sleuth Kit and other digital forensics tools. It can be used by law enforcement, military, and corporate examiners to investigate what happened on a computer.",
      category: "Forensics",
      difficulty: "Intermediate",
      lastUpdated: "2024-01-17",
      officialSite: "https://www.autopsy.com",
      icon: "🔬",
      whatItIs: "A comprehensive digital forensics platform with an intuitive graphical interface.",
      whatItsUsedFor: "Used by digital forensics examiners to analyze hard drives, mobile devices, and network traffic in criminal investigations and incident response.",
      howItWorks: "Provides a case management system and automated analysis modules to examine digital evidence, recover deleted files, and generate forensic reports.",
      commands: [
        "Launch Autopsy GUI application",
        "Create new case",
        "Add data source (disk image, device)",
        "Run ingest modules and analysis"
      ],
      results: [
        "Case created: Investigation_2024_001",
        "Disk image processed: 500GB analyzed",
        "Recovered 15,000 deleted files",
        "Generated timeline of user activity"
      ],
      useCases: [
        "Criminal investigations",
        "Corporate incident response",
        "Data recovery",
        "Digital evidence analysis"
      ],
      features: [
        "Graphical user interface",
        "Case management system",
        "Automated analysis modules",
        "Timeline generation",
        "Report generation"
      ],
      installSteps: [
        "Download from official website",
        "Install Java Runtime Environment",
        "Run installer package",
        "Launch Autopsy application"
      ],
      basicUsage: [
        "Start Autopsy",
        "Create new case",
        "Add evidence source",
        "Configure ingest modules"
      ]
    },
    {
      id: "wireshark",
      name: "Wireshark",
      fullName: "Wireshark Network Protocol Analyzer",
      description: "Network protocol analyzer for troubleshooting and analysis",
      longDescription: "Wireshark is the world's foremost and widely-used network protocol analyzer. It lets you see what's happening on your network at a microscopic level and is the de facto standard across many commercial and non-profit enterprises.",
      category: "Forensics",
      difficulty: "Intermediate",
      lastUpdated: "2024-01-21",
      officialSite: "https://www.wireshark.org",
      icon: "🦈",
      whatItIs: "The world's most popular network protocol analyzer for detailed packet inspection.",
      whatItsUsedFor: "Used by network administrators, security analysts, and forensics investigators to troubleshoot network issues, analyze traffic, and investigate security incidents.",
      howItWorks: "Captures and analyzes network packets in real-time or from saved capture files, providing detailed protocol information and traffic analysis.",
      commands: [
        "wireshark",
        "tshark -i eth0 -w capture.pcap",
        "tshark -r capture.pcap -Y 'http.request'",
        "dumpcap -i eth0 -w output.pcap"
      ],
      results: [
        "Wireshark started successfully",
        "Captured 10,000 packets in 5 minutes",
        "Found 45 HTTP requests",
        "Detected suspicious traffic patterns"
      ],
      useCases: [
        "Network troubleshooting",
        "Security analysis",
        "Protocol development",
        "Network forensics"
      ],
      features: [
        "Live packet capture",
        "Deep protocol inspection",
        "Rich VoIP analysis",
        "Powerful display filters",
        "Cross-platform support"
      ],
      installSteps: [
        "Download from official website",
        "Install package: sudo apt install wireshark",
        "Add user to wireshark group",
        "Launch: wireshark"
      ],
      basicUsage: [
        "Start capture: Select interface and click start",
        "Apply filters: Use display filter bar",
        "Save capture: File > Save As",
        "Analyze protocols: Statistics menu"
      ]
    },
    {
      id: "sleuthkit",
      name: "The Sleuth Kit",
      fullName: "The Sleuth Kit Digital Investigation Tools",
      description: "Collection of command line digital forensics tools",
      longDescription: "The Sleuth Kit (TSK) is a library and collection of command line digital forensics tools that allows you to investigate volume and file system data.",
      category: "Forensics",
      difficulty: "Advanced",
      lastUpdated: "2024-01-15",
      officialSite: "https://www.sleuthkit.org",
      icon: "🔍",
      whatItIs: "A collection of powerful command-line tools for digital forensics investigations.",
      whatItsUsedFor: "Used by forensics experts to analyze file systems, recover deleted files, and examine disk images at a low level.",
      howItWorks: "Provides command-line tools to analyze file systems independently of the operating system, allowing examination of damaged or foreign file systems.",
      commands: [
        "mmls disk.img",
        "fsstat -f ext3 disk.img",
        "fls -r disk.img",
        "icat disk.img 1234 > recovered_file.txt"
      ],
      results: [
        "Partition table found: 3 partitions",
        "File system: ext3, block size: 4096",
        "Directory listing: 1,500 files found",
        "File recovered successfully"
      ],
      useCases: [
        "File system analysis",
        "Deleted file recovery",
        "Timeline creation",
        "Low-level disk examination"
      ],
      features: [
        "Multiple file system support",
        "Timeline generation",
        "Hash database lookup",
        "Metadata analysis",
        "Cross-platform compatibility"
      ],
      installSteps: [
        "Install via package manager: sudo apt install sleuthkit",
        "Or compile from source",
        "Verify: mmls -V",
        "Test with disk image"
      ],
      basicUsage: [
        "List partitions: mmls [image]",
        "File system info: fsstat [image]",
        "List files: fls [image]",
        "Extract file: icat [image] [inode]"
      ]
    },
    {
      id: "foremost",
      name: "Foremost",
      fullName: "Foremost File Carving Tool",
      description: "File carving tool for recovering files based on headers and footers",
      longDescription: "Foremost is a console program to recover files based on their headers, footers, and internal data structures. This process is commonly referred to as data carving.",
      category: "Forensics",
      difficulty: "Beginner",
      lastUpdated: "2024-01-10",
      officialSite: "http://foremost.sourceforge.net",
      icon: "🗂️",
      whatItIs: "A data carving tool that recovers files based on file signatures and data structures.",
      whatItsUsedFor: "Used by forensics investigators to recover deleted files from disk images, USB drives, and other storage media.",
      howItWorks: "Scans data for file signatures (headers and footers) to identify and extract files even when the file system is damaged or deleted.",
      commands: [
        "foremost -i disk.img -o output/",
        "foremost -t jpeg,pdf -i evidence.dd -o recovered/",
        "foremost -v -i /dev/sdb1 -o /tmp/recovery/",
        "foremost -c custom.conf -i data.img -o results/"
      ],
      results: [
        "Foremost version 1.5.7 started",
        "Recovered 45 JPEG files",
        "Recovered 12 PDF documents",
        "Processing completed: 2.3GB scanned"
      ],
      useCases: [
        "Deleted file recovery",
        "Data carving from damaged media",
        "Digital evidence recovery",
        "Data loss investigation"
      ],
      features: [
        "Multiple file type support",
        "Custom configuration files",
        "Bulk file recovery",
        "Command-line interface",
        "Fast scanning algorithms"
      ],
      installSteps: [
        "Install via package manager: sudo apt install foremost",
        "Or compile from source",
        "Test installation: foremost -V",
        "Check config: /etc/foremost.conf"
      ],
      basicUsage: [
        "Basic recovery: foremost -i [input] -o [output]",
        "Specific types: foremost -t [types] -i [input] -o [output]",
        "Verbose mode: foremost -v -i [input] -o [output]",
        "Custom config: foremost -c [config] -i [input] -o [output]"
      ]
    }
  ],

  "web-application-assessment": [
    {
      id: "owasp-zap",
      name: "OWASP ZAP",
      fullName: "OWASP Zed Attack Proxy",
      description: "Free security testing proxy for web applications",
      longDescription: "OWASP ZAP is one of the world's most popular free security tools and is actively maintained by hundreds of international volunteers. It can help you automatically find security vulnerabilities in your web applications while developing and testing.",
      category: "Web Application Assessment",
      difficulty: "Beginner",
      lastUpdated: "2024-01-22",
      officialSite: "https://www.zaproxy.org",
      icon: "⚡",
      whatItIs: "A comprehensive web application security scanner with an intuitive interface.",
      whatItsUsedFor: "Used by developers and security testers to identify vulnerabilities in web applications during development and testing phases.",
      howItWorks: "Acts as an intercepting proxy between the browser and web application, performing automated and manual security tests to identify vulnerabilities.",
      commands: [
        "zap.sh",
        "Configure browser proxy to ZAP",
        "Spider target application",
        "Run active scan"
      ],
      results: [
        "ZAP started on port 8080",
        "Spider completed: 150 URLs discovered",
        "Active scan found 23 vulnerabilities",
        "Report generated successfully"
      ],
      useCases: [
        "Web application penetration testing",
        "DevSecOps integration",
        "API security testing",
        "Automated security scanning"
      ],
      features: [
        "Intercepting proxy",
        "Automated scanner",
        "Manual testing tools",
        "API testing support",
        "Extensive reporting"
      ],
      installSteps: [
        "Download from official website",
        "Install Java Runtime Environment",
        "Run installer or extract archive",
        "Launch ZAP application"
      ],
      basicUsage: [
        "Start ZAP application",
        "Configure browser proxy",
        "Browse target application",
        "Run automated scans"
      ]
    },
    {
      id: "dirb",
      name: "DIRB",
      fullName: "DIRB Web Content Scanner",
      description: "Web content scanner for finding hidden directories and files",
      longDescription: "DIRB is a Web Content Scanner. It looks for existing (and/or hidden) Web Objects. It basically works by launching a dictionary based attack against a web server and analyzing the response.",
      category: "Web Application Assessment",
      difficulty: "Beginner",
      lastUpdated: "2024-01-14",
      officialSite: "http://dirb.sourceforge.net",
      icon: "📁",
      whatItIs: "A web content scanner that discovers hidden directories and files on web servers.",
      whatItsUsedFor: "Used by penetration testers to discover hidden web content, backup files, and administrative interfaces that may contain vulnerabilities.",
      howItWorks: "Performs dictionary-based attacks against web servers, testing for the existence of directories and files using wordlists.",
      commands: [
        "dirb https://example.com",
        "dirb https://example.com /usr/share/dirb/wordlists/common.txt",
        "dirb https://example.com -o results.txt",
        "dirb https://example.com -x extensions.txt"
      ],
      results: [
        "DIRB v2.22 scan started",
        "Found directory: /admin/",
        "Found file: /backup.sql",
        "Scan completed: 15 objects found"
      ],
      useCases: [
        "Hidden content discovery",
        "Web application reconnaissance",
        "Security assessments",
        "Penetration testing"
      ],
      features: [
        "Dictionary-based scanning",
        "Custom wordlists",
        "Extension testing",
        "Recursive scanning",
        "Session handling"
      ],
      installSteps: [
        "Install via package manager: sudo apt install dirb",
        "Or compile from source",
        "Test installation: dirb",
        "Check wordlists: ls /usr/share/dirb/wordlists/"
      ],
      basicUsage: [
        "Basic scan: dirb [URL]",
        "Custom wordlist: dirb [URL] [wordlist]",
        "Save output: dirb [URL] -o [output]",
        "File extensions: dirb [URL] -X [extensions]"
      ]
    },
    {
      id: "gobuster",
      name: "Gobuster",
      fullName: "Gobuster Directory/File Brute-forcer",
      description: "Fast directory/file brute-forcer written in Go",
      longDescription: "Gobuster is a tool used to brute-force URIs (directories and files) in web sites, DNS subdomains (with wildcard support), Virtual Host names on target web servers, Amazon S3 buckets.",
      category: "Web Application Assessment",
      difficulty: "Beginner",
      lastUpdated: "2024-01-16",
      officialSite: "https://github.com/OJ/gobuster",
      icon: "🚀",
      whatItIs: "A fast and efficient directory and file brute-forcing tool written in Go.",
      whatItsUsedFor: "Used for discovering hidden web content, directories, files, and subdomains during web application security assessments.",
      howItWorks: "Performs high-speed brute force attacks against web servers, DNS, and virtual hosts using customizable wordlists.",
      commands: [
        "gobuster dir -u https://example.com -w wordlist.txt",
        "gobuster dns -d example.com -w subdomains.txt",
        "gobuster vhost -u https://example.com -w vhosts.txt",
        "gobuster s3 -w bucket_names.txt"
      ],
      results: [
        "Gobuster v3.1.0 started",
        "Found: /admin (Status: 200)",
        "Found: /backup.zip (Status: 200)",
        "Finished scanning 10,000 entries"
      ],
      useCases: [
        "Directory enumeration",
        "Subdomain discovery",
        "Virtual host enumeration",
        "S3 bucket discovery"
      ],
      features: [
        "High-speed scanning",
        "Multiple scan modes",
        "Custom status codes",
        "Proxy support",
        "Wildcard detection"
      ],
      installSteps: [
        "Download from GitHub releases",
        "Or install with Go: go install github.com/OJ/gobuster/v3@latest",
        "Make executable: chmod +x gobuster",
        "Test: gobuster version"
      ],
      basicUsage: [
        "Directory scan: gobuster dir -u [URL] -w [wordlist]",
        "DNS scan: gobuster dns -d [domain] -w [wordlist]",
        "Virtual host: gobuster vhost -u [URL] -w [wordlist]",
        "S3 buckets: gobuster s3 -w [wordlist]"
      ]
    },
    {
      id: "ffuf",
      name: "ffuf",
      fullName: "Fuzz Faster U Fool",
      description: "Fast web fuzzer written in Go",
      longDescription: "ffuf is a fast web fuzzer written in Go that allows typical directory discovery, virtual host discovery (without DNS records) and GET and POST parameter fuzzing.",
      category: "Web Application Assessment",
      difficulty: "Intermediate",
      lastUpdated: "2024-01-12",
      officialSite: "https://github.com/ffuf/ffuf",
      icon: "💨",
      whatItIs: "A fast and flexible web fuzzer for discovering hidden content and testing parameters.",
      whatItsUsedFor: "Used for web application fuzzing including directory discovery, parameter testing, and virtual host enumeration.",
      howItWorks: "Sends HTTP requests with different payloads to discover hidden content, test parameters, and identify potential vulnerabilities through fuzzing.",
      commands: [
        "ffuf -w wordlist.txt -u https://example.com/FUZZ",
        "ffuf -w wordlist.txt -u https://example.com/ -H 'Host: FUZZ.example.com'",
        "ffuf -w params.txt -u https://example.com/admin -d 'FUZZ=test'",
        "ffuf -w extensions.txt -u https://example.com/indexFUZZ"
      ],
      results: [
        "ffuf v1.5.0 started",
        "200: /admin (Size: 1234)",
        "403: /backup (Size: 567)",
        "Completed: 15,000 requests"
      ],
      useCases: [
        "Directory fuzzing",
        "Parameter fuzzing",
        "Virtual host discovery",
        "File extension testing"
      ],
      features: [
        "High performance fuzzing",
        "Flexible matching/filtering",
        "Multiple HTTP methods",
        "Custom headers support",
        "Output formatting options"
      ],
      installSteps: [
        "Download from GitHub releases",
        "Or install with Go: go install github.com/ffuf/ffuf@latest",
        "Make executable: chmod +x ffuf",
        "Test: ffuf -V"
      ],
      basicUsage: [
        "Directory fuzz: ffuf -w [wordlist] -u [URL]/FUZZ",
        "Vhost fuzz: ffuf -w [wordlist] -u [URL] -H 'Host: FUZZ.domain.com'",
        "Parameter fuzz: ffuf -w [wordlist] -u [URL] -d 'FUZZ=value'",
        "Extension fuzz: ffuf -w [wordlist] -u [URL]/fileFUZZ"
      ]
    },
    {
      id: "wapiti",
      name: "Wapiti",
      fullName: "Wapiti Web Application Vulnerability Scanner",
      description: "Web application vulnerability scanner",
      longDescription: "Wapiti allows you to audit the security of your websites or web applications. It performs 'black-box' scans (it does not study the source code) of the web application by crawling the webpages of the deployed webapp, looking for scripts and forms where it can inject data.",
      category: "Web Application Assessment",
      difficulty: "Intermediate",
      lastUpdated: "2024-01-08",
      officialSite: "http://wapiti.sourceforge.net",
      icon: "🕷️",
      whatItIs: "A black-box web application vulnerability scanner that crawls and tests web applications.",
      whatItsUsedFor: "Used to identify vulnerabilities in web applications by performing automated security tests against forms, parameters, and cookies.",
      howItWorks: "Crawls web applications to identify injection points, then performs various attacks to detect vulnerabilities like SQL injection, XSS, and file inclusion.",
      commands: [
        "wapiti -u https://example.com",
        "wapiti -u https://example.com -f txt -o report.txt",
        "wapiti -u https://example.com -m 'xss,sqli'",
        "wapiti -u https://example.com --scope=domain"
      ],
      results: [
        "Wapiti 3.1.3 scan started",
        "Crawled 45 pages successfully",
        "Found SQL injection in /search.php",
        "Found XSS vulnerability in /contact.php"
      ],
      useCases: [
        "Web application security testing",
        "Vulnerability assessment",
        "Penetration testing",
        "Security auditing"
      ],
      features: [
        "Multiple vulnerability types",
        "Web application crawling",
        "Various report formats",
        "Modular attack system",
        "Authentication support"
      ],
      installSteps: [
        "Install Python 3: sudo apt install python3-pip",
        "Install Wapiti: pip3 install wapiti3",
        "Or install from package: sudo apt install wapiti",
        "Test: wapiti --version"
      ],
      basicUsage: [
        "Basic scan: wapiti -u [URL]",
        "Specific modules: wapiti -u [URL] -m [modules]",
        "Output format: wapiti -u [URL] -f [format] -o [file]",
        "Scope control: wapiti -u [URL] --scope=[scope]"
      ]
    }
  ]
};

export const getToolsByCategory = (category: string): Tool[] => {
  const categoryKey = category.toLowerCase().replace(/\s+/g, '-');
  return toolsData[categoryKey] || [];
};

export const getToolById = (id: string): Tool | undefined => {
  for (const category of Object.values(toolsData)) {
    const tool = category.find(tool => tool.id === id);
    if (tool) return tool;
  }
  return undefined;
};

export const getAllTools = (): Tool[] => {
  return Object.values(toolsData).flat();
};

export const searchTools = (query: string): Tool[] => {
  const allTools = getAllTools();
  const lowercaseQuery = query.toLowerCase();
  
  return allTools.filter(tool => 
    tool.name.toLowerCase().includes(lowercaseQuery) ||
    tool.description.toLowerCase().includes(lowercaseQuery) ||
    tool.category.toLowerCase().includes(lowercaseQuery)
  );
};

export const categories = [
  { 
    name: "Information Gathering", 
    description: "Tools for reconnaissance and intelligence gathering",
    icon: "🔍",
    count: getToolsByCategory("Information Gathering").length
  },
  { 
    name: "Wireless Hacking", 
    description: "WiFi and wireless network security tools",
    icon: "📡",
    count: getToolsByCategory("Wireless Hacking").length
  },
  { 
    name: "Phishing & Social Engineering", 
    description: "Social engineering and phishing simulation tools",
    icon: "🎭",
    count: getToolsByCategory("Phishing & Social Engineering").length
  },
  { 
    name: "Exploitation", 
    description: "Vulnerability exploitation and payload frameworks",
    icon: "💥",
    count: getToolsByCategory("Exploitation").length
  },
  { 
    name: "Password Cracking", 
    description: "Password recovery and authentication testing",
    icon: "🔓",
    count: getToolsByCategory("Password Cracking").length
  },
  { 
    name: "Vulnerability Scanning", 
    description: "Automated vulnerability detection and assessment",
    icon: "🛡️",
    count: getToolsByCategory("Vulnerability Scanning").length
  },
  { 
    name: "Forensics", 
    description: "Digital forensics and incident response tools",
    icon: "🔬",
    count: getToolsByCategory("Forensics").length
  },
  { 
    name: "Web Application Assessment", 
    description: "Web application security testing and analysis",
    icon: "🌐",
    count: getToolsByCategory("Web Application Assessment").length
  }
];