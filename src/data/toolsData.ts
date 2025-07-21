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
  downloadUrl?: string;
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
  advancedExamples: string[];
  realWorldScenarios: string[];
  troubleshooting: string[];
  securityTips: string[];
  platform?: "Windows" | "Linux" | "macOS" | "Cross-platform";
  license?: "Free" | "Commercial" | "Open Source";
}

export const toolsData: Record<string, Tool[]> = {
  "information-gathering": [
    {
      id: "ip-lookup",
      name: "IP Lookup",
      fullName: "IP Address Lookup & Geolocation Tool",
      description: "Real-time IP address information and geolocation service",
      longDescription: "IP Lookup is a comprehensive tool for analyzing IP addresses, providing detailed information about geographical location, ISP details, organization data, and potential security threats associated with specific IP addresses.",
      category: "Information Gathering",
      difficulty: "Beginner",
      lastUpdated: "2024-01-20",
      officialSite: "https://whatismyipaddress.com",
      downloadUrl: "https://whatismyipaddress.com/ip-lookup",
      platform: "Cross-platform",
      license: "Free",
      icon: "🌐",
      whatItIs: "A web-based and command-line tool for retrieving detailed information about IP addresses including geolocation, ISP, and security data.",
      whatItsUsedFor: "Security analysts use IP lookup tools to investigate suspicious network activity, track the origin of attacks, verify user locations, and gather intelligence during forensic investigations.",
      howItWorks: "The tool queries multiple databases containing IP address allocations, geolocation data, and threat intelligence to provide comprehensive information about a target IP address.",
      commands: [
        "curl ipinfo.io/8.8.8.8",
        "nslookup 8.8.8.8",
        "whois 8.8.8.8",
        "dig -x 8.8.8.8",
        "curl 'https://ipapi.co/8.8.8.8/json/'",
        "traceroute 8.8.8.8"
      ],
      results: [
        "IP: 8.8.8.8, Location: Mountain View, CA, ISP: Google LLC",
        "Hostname: dns.google, Organization: Google Public DNS",
        "Country: United States, Region: California, Timezone: America/Los_Angeles",
        "ASN: AS15169, Threat Level: Low, VPN/Proxy: No",
        "Coordinates: 37.4056, -122.0775, Accuracy: City level"
      ],
      useCases: [
        "Investigating suspicious login attempts from unknown locations",
        "Verifying the geographical location of website visitors",
        "Tracking the source of cyber attacks and malicious traffic",
        "Compliance checking for geo-restricted content delivery",
        "Forensic analysis of network logs and security incidents"
      ],
      features: [
        "Real-time IP geolocation with city-level accuracy",
        "ISP and organization identification",
        "Threat intelligence integration",
        "VPN/Proxy detection capabilities",
        "Historical IP data analysis",
        "Bulk IP lookup functionality",
        "API integration support",
        "Export results in multiple formats"
      ],
      installSteps: [
        "No installation required for web-based tools",
        "For command-line: Install curl (usually pre-installed)",
        "For advanced features: Register for API access at ipinfo.io",
        "Alternative: Install dedicated tools like 'geoip' or 'ipinfo-cli'",
        "Verify connectivity: curl ipinfo.io/json"
      ],
      basicUsage: [
        "Web Interface: Visit whatismyipaddress.com and enter target IP",
        "Command Line: curl ipinfo.io/[IP_ADDRESS]",
        "Get your own IP: curl ipinfo.io",
        "JSON format: curl ipinfo.io/8.8.8.8/json",
        "Specific field: curl ipinfo.io/8.8.8.8/city"
      ],
      advancedExamples: [
        "Bulk lookup: for ip in $(cat ip_list.txt); do curl ipinfo.io/$ip; done",
        "Threat analysis: curl ipinfo.io/[IP]/threat | jq '.threat_level'",
        "ASN lookup: whois -h whois.cymru.com ' -v [IP_ADDRESS]'",
        "Reverse DNS: dig -x [IP_ADDRESS] +short",
        "Traceroute analysis: traceroute [IP_ADDRESS] | grep -E '[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+'"
      ],
      realWorldScenarios: [
        "Incident Response: Analyzing the source of a DDoS attack by looking up attacking IP addresses",
        "Fraud Detection: Verifying if user login locations match expected geographical patterns",
        "Content Delivery: Determining optimal server locations based on user IP distributions",
        "Compliance Audit: Ensuring access restrictions are properly enforced by geography",
        "Threat Hunting: Correlating suspicious IPs with known threat actor infrastructure"
      ],
      troubleshooting: [
        "Rate limiting: Some services limit queries per hour - use API keys for higher limits",
        "Accuracy issues: IP geolocation can be inaccurate for mobile/VPN traffic",
        "False positives: Cross-reference results from multiple services for accuracy",
        "API errors: Check your internet connection and API key validity",
        "Outdated data: Use multiple sources as IP allocations change frequently"
      ],
      securityTips: [
        "Never rely solely on IP geolocation for security decisions",
        "Be aware that VPNs and proxies can mask true user locations",
        "Use IP reputation services alongside geolocation data",
        "Log and monitor IP lookup activities for audit trails",
        "Respect privacy laws when collecting and storing IP data",
        "Implement rate limiting to prevent abuse of lookup services"
      ]
    },
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
      downloadUrl: "https://nmap.org/download.html",
      platform: "Cross-platform",
      license: "Open Source",
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
      ],
      advancedExamples: [
        "Stealth scan with decoys: nmap -sS -D RND:10 target.com",
        "Script scan for vulnerabilities: nmap --script vuln target.com",
        "Timing template for faster scans: nmap -T4 -A target.com",
        "Output to XML for parsing: nmap -oX scan_results.xml target.com"
      ],
      realWorldScenarios: [
        "Network Discovery: Scan corporate network to identify all active devices and create network inventory",
        "Security Audit: Check web server for open ports and running services before deployment",
        "Incident Response: Quickly assess compromised network segment for additional threats",
        "Compliance Check: Verify firewall rules by testing blocked/allowed ports"
      ],
      troubleshooting: [
        "Slow scans: Use timing templates (-T0 to -T5) to adjust scan speed",
        "Firewall blocking: Try different scan types (-sS, -sT, -sA) or use decoys",
        "Permission denied: Run with sudo for SYN scans and OS detection",
        "No response: Target might be down or heavily filtered - try ping scan first"
      ],
      securityTips: [
        "Always get written permission before scanning networks you don't own",
        "Use rate limiting (-T1 or -T2) to avoid triggering IDS/IPS systems",
        "Scan from different source IPs to avoid being blocked",
        "Keep Nmap updated to ensure latest vulnerability detection scripts"
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
        "masscan -p443 --banners 192.168.1.0/24"
      ],
      results: [
        "Discovered open port 80/tcp on 10.0.1.45",
        "Discovered open port 8080/tcp on 10.0.2.123",
        "Rate: 1000.00-kpps, 0:01:23 remaining",
        "Banner on port 443/tcp: HTTP/1.1 200 OK"
      ],
      useCases: [
        "Large-scale network reconnaissance",
        "Internet-wide research scanning",
        "Rapid port discovery for penetration testing",
        "Network security assessment"
      ],
      features: [
        "Asynchronous transmission",
        "Custom TCP/IP stack",
        "Banner grabbing",
        "High-speed scanning",
        "Flexible output formats"
      ],
      installSteps: [
        "Clone from GitHub: git clone https://github.com/robertdavidgraham/masscan",
        "Install dependencies: sudo apt-get install gcc make libpcap-dev",
        "Compile: cd masscan && make",
        "Install: sudo make install"
      ],
      basicUsage: [
        "Scan common ports: masscan -p80,443 192.168.1.0/24",
        "Set scan rate: masscan --rate=1000 -p80 target.com",
        "Save results: masscan -p80 192.168.1.0/24 -oX output.xml",
        "Scan with banners: masscan --banners -p80 target.com"
      ],
      advancedExamples: [
        "Exclude ranges: masscan -p80 0.0.0.0/0 --excludefile exclude.txt",
        "Resume scan: masscan --resume paused.conf",
        "Custom source port: masscan -p80 --source-port 61000 target.com",
        "Router MAC: masscan -p80 --router-mac 00:11:22:33:44:55 target.com"
      ],
      realWorldScenarios: [
        "Bug Bounty: Quickly scan entire company IP ranges for exposed services",
        "Threat Intelligence: Monitor internet for new services on known bad IPs",
        "Asset Discovery: Find all web services across multiple data centers",
        "Security Monitoring: Detect unexpected services on corporate networks"
      ],
      troubleshooting: [
        "Rate too high: Reduce --rate parameter if packets are dropped",
        "Permission denied: Run with sudo or set raw socket capabilities",
        "No output: Check firewall settings and network connectivity",
        "Memory issues: Use --max-rate to limit resource usage"
      ],
      securityTips: [
        "Start with low rates to avoid overwhelming target networks",
        "Use exclude files to avoid scanning restricted ranges",
        "Monitor your scanning to ensure you're not being blocked",
        "Always comply with terms of service and legal requirements"
      ]
    },
    {
      id: "shodan",
      name: "Shodan",
      fullName: "Shodan Search Engine",
      description: "Search engine for Internet-connected devices and services",
      longDescription: "Shodan is a search engine that lets users find specific types of computers (webcams, routers, servers, etc.) connected to the internet using a variety of filters.",
      category: "Information Gathering",
      difficulty: "Advanced",
      lastUpdated: "2024-01-12",
      officialSite: "https://www.shodan.io",
      downloadUrl: "https://cli.shodan.io",
      platform: "Cross-platform",
      license: "Commercial",
      icon: "🌐",
      whatItIs: "A specialized search engine that indexes internet-connected devices and their services.",
      whatItsUsedFor: "Security researchers use Shodan to discover exposed devices, vulnerable services, and gather intelligence about internet infrastructure.",
      howItWorks: "Shodan continuously scans the entire IPv4 address space, collecting banner information from services running on various ports, then indexes this data for search.",
      commands: [
        "shodan search apache",
        "shodan host 8.8.8.8",
        "shodan count country:US",
        "shodan download query.json.gz apache"
      ],
      results: [
        "Found 2,451,789 results for apache",
        "Host 8.8.8.8: Google DNS server",
        "Count for country:US - 45,678,901",
        "Downloaded 100,000 results to query.json.gz"
      ],
      useCases: [
        "Internet-wide device discovery",
        "Vulnerability research",
        "Threat intelligence gathering",
        "Digital forensics investigations"
      ],
      features: [
        "Global device scanning",
        "Service banner collection",
        "Geolocation data",
        "Historical data access",
        "API integration"
      ],
      installSteps: [
        "Install Python package: pip install shodan",
        "Get API key from shodan.io account",
        "Initialize: shodan init YOUR_API_KEY",
        "Test connection: shodan info"
      ],
      basicUsage: [
        "Search devices: shodan search 'product:Apache'",
        "Get host info: shodan host [IP_ADDRESS]",
        "Count results: shodan count [QUERY]",
        "Download data: shodan download [filename] [query]"
      ],
      advancedExamples: [
        "Find specific cameras: shodan search 'Server: SQ-WEBCAM'",
        "Industrial systems: shodan search 'port:502 country:US'",
        "SSL certificates: shodan search 'ssl:\"Lets Encrypt\"'",
        "Vulnerable versions: shodan search 'apache/2.2.15 country:US'"
      ],
      realWorldScenarios: [
        "IoT Security Research: Identify exposed IoT devices for vulnerability assessment",
        "Threat Hunting: Monitor for new exposed services in your organization's IP ranges",
        "Compliance Auditing: Verify that internal services aren't exposed to the internet",
        "Incident Response: Track compromised infrastructure across the internet"
      ],
      troubleshooting: [
        "API limits: Upgrade account or use filters to reduce result count",
        "No results: Verify search syntax and try broader queries",
        "Rate limiting: Space out requests or use bulk download features",
        "Authentication: Ensure API key is properly configured"
      ],
      securityTips: [
        "Use responsibly - don't access devices without permission",
        "Respect rate limits to maintain access to the service",
        "Monitor your own infrastructure using Shodan alerts",
        "Keep API keys secure and rotate them regularly"
      ]
    }
  ],
  "vulnerability-analysis": [
    {
      id: "nikto",
      name: "Nikto",
      fullName: "Nikto Web Vulnerability Scanner",
      description: "Open source web server scanner for vulnerabilities",
      longDescription: "Nikto is an Open Source web server scanner which performs comprehensive tests against web servers for multiple items, including over 6700 potentially dangerous files/programs.",
      category: "Vulnerability Analysis",
      difficulty: "Beginner",
      lastUpdated: "2024-01-08",
      officialSite: "https://cirt.net/Nikto2",
      downloadUrl: "https://github.com/sullo/nikto",
      platform: "Cross-platform",
      license: "Open Source",
      icon: "🔎",
      whatItIs: "A comprehensive web vulnerability scanner that tests for thousands of known security issues.",
      whatItsUsedFor: "Web application security testing, identifying common vulnerabilities, misconfigurations, and dangerous files on web servers.",
      howItWorks: "Scans web servers by sending HTTP requests to test for known vulnerabilities, outdated software versions, dangerous files, and server misconfigurations.",
      commands: [
        "nikto -h target.com",
        "nikto -h target.com -p 80,443",
        "nikto -h target.com -o report.html",
        "nikto -h target.com -T 1,2,3"
      ],
      results: [
        "Found 15 vulnerabilities on target.com",
        "Outdated Apache version detected",
        "Potentially dangerous file: /admin/config.php",
        "Missing security headers detected"
      ],
      useCases: [
        "Web application penetration testing",
        "Security compliance auditing",
        "Vulnerability assessment",
        "Security baseline establishment"
      ],
      features: [
        "6700+ vulnerability checks",
        "SSL/TLS testing",
        "Multiple output formats",
        "Plugin architecture",
        "Cookie analysis"
      ],
      installSteps: [
        "Install via package manager: sudo apt install nikto",
        "Or clone from GitHub: git clone https://github.com/sullo/nikto.git",
        "Update database: nikto -update",
        "Run test scan: nikto -h localhost"
      ],
      basicUsage: [
        "Basic scan: nikto -h [target]",
        "Scan specific port: nikto -h [target] -p [port]",
        "Output to file: nikto -h [target] -o [filename]",
        "Specific tests: nikto -h [target] -T [test_numbers]"
      ],
      advancedExamples: [
        "Authenticated scan: nikto -h target.com -id username:password",
        "Custom user agent: nikto -h target.com -useragent 'Custom Agent'",
        "Through proxy: nikto -h target.com -useproxy http://proxy:8080",
        "SSL with SNI: nikto -h target.com -ssl -vhost virtualhost.com"
      ],
      realWorldScenarios: [
        "Pre-deployment Testing: Scan new web applications before going live",
        "Compliance Auditing: Regular scans to ensure ongoing security compliance",
        "Incident Response: Quick assessment of potentially compromised web servers",
        "Security Baseline: Establish security posture for new web services"
      ],
      troubleshooting: [
        "Connection timeouts: Increase timeout with -timeout option",
        "False positives: Use -T option to run specific test categories",
        "SSL errors: Try -ssl flag or check certificate configuration",
        "Rate limiting: Use -Pause option to slow down requests"
      ],
      securityTips: [
        "Always get authorization before scanning external websites",
        "Use rate limiting to avoid overwhelming target servers",
        "Regularly update the vulnerability database",
        "Review results carefully to distinguish real vulnerabilities from false positives"
      ]
    },
    {
      id: "openvas",
      name: "OpenVAS",
      fullName: "Open Vulnerability Assessment System",
      description: "Comprehensive vulnerability scanning and management solution",
      longDescription: "OpenVAS is a full-featured vulnerability scanner that includes thousands of vulnerability tests and can manage large-scale vulnerability assessments.",
      category: "Vulnerability Analysis",
      difficulty: "Beginner",
      lastUpdated: "2024-01-05",
      officialSite: "https://www.openvas.org",
      downloadUrl: "https://www.greenbone.net/en/install_openvas/",
      platform: "Linux",
      license: "Open Source",
      icon: "🛡️",
      whatItIs: "A comprehensive vulnerability assessment framework with web-based management interface.",
      whatItsUsedFor: "Enterprise vulnerability management, compliance reporting, network security assessment, and continuous security monitoring.",
      howItWorks: "Uses a client-server architecture where the scanner daemon performs vulnerability tests while the web interface manages scans, reports, and vulnerability data.",
      commands: [
        "sudo systemctl start openvas-scanner",
        "sudo systemctl start openvas-manager",
        "openvas-setup",
        "openvas-check-setup"
      ],
      results: [
        "Scan completed: 45 hosts, 234 vulnerabilities found",
        "High: 12, Medium: 156, Low: 66",
        "Critical systems identified: Database server",
        "Compliance report generated successfully"
      ],
      useCases: [
        "Enterprise vulnerability management",
        "PCI DSS compliance scanning",
        "Network security assessment",
        "Continuous security monitoring"
      ],
      features: [
        "50,000+ vulnerability tests",
        "Web-based interface",
        "Scheduled scanning",
        "Report generation",
        "Asset management"
      ],
      installSteps: [
        "Add repository: sudo add-apt-repository ppa:mrazavi/openvas",
        "Update packages: sudo apt update",
        "Install: sudo apt install openvas",
        "Setup: sudo openvas-setup"
      ],
      basicUsage: [
        "Access web interface: https://localhost:9392",
        "Create scan config in Configurations > Scan Configs",
        "Add target in Configuration > Targets",
        "Create new task in Scans > Tasks"
      ],
      advancedExamples: [
        "Custom scan config: Create targeted scan for specific vulnerability types",
        "Authenticated scans: Configure SSH/SMB credentials for deeper scanning",
        "Delta scans: Compare current scan with previous results",
        "API integration: Use OMP protocol for automated scan management"
      ],
      realWorldScenarios: [
        "Enterprise Assessment: Regular automated scans of entire corporate network",
        "Compliance Reporting: Generate PCI DSS compliance reports for payment systems",
        "Patch Management: Identify missing security patches across infrastructure",
        "Incident Response: Rapid vulnerability assessment after security incidents"
      ],
      troubleshooting: [
        "Scanner not starting: Check system resources and log files",
        "Database errors: Ensure PostgreSQL is properly configured",
        "Web interface not accessible: Verify HTTPS certificate and firewall",
        "Slow scans: Adjust scan preferences and reduce concurrent tasks"
      ],
      securityTips: [
        "Change default passwords immediately after installation",
        "Keep vulnerability feeds updated regularly",
        "Use strong SSL certificates for web interface",
        "Implement proper network segmentation for scanner deployment"
      ]
    }
  ],
  "wireless-security": [
    {
      id: "aircrack-ng",
      name: "Aircrack-ng",
      fullName: "Aircrack-ng Wireless Security Suite",
      description: "Complete suite of tools for wireless network security assessment",
      longDescription: "Aircrack-ng is a complete suite of tools to assess WiFi network security. It focuses on different areas of WiFi security: monitoring, attacking, testing, and cracking.",
      category: "Wireless Security",
      difficulty: "Intermediate",
      lastUpdated: "2024-01-20",
      officialSite: "https://www.aircrack-ng.org",
      downloadUrl: "https://www.aircrack-ng.org/downloads.html",
      platform: "Cross-platform",
      license: "Open Source",
      icon: "📡",
      whatItIs: "A comprehensive wireless network security auditing suite.",
      whatItsUsedFor: "Wireless penetration testing, WEP/WPA/WPA2 cracking, wireless network monitoring, and security assessment.",
      howItWorks: "Captures and analyzes wireless network traffic, performs various attacks against wireless networks, and attempts to crack wireless encryption keys.",
      commands: [
        "airmon-ng start wlan0",
        "airodump-ng wlan0mon",
        "aireplay-ng -0 10 -a BSSID wlan0mon",
        "aircrack-ng -w wordlist.txt capture.cap"
      ],
      results: [
        "Monitor mode enabled on wlan0mon",
        "Found 5 wireless networks, 12 clients",
        "Deauth attack sent to target client",
        "WPA key found: password123"
      ],
      useCases: [
        "Wireless penetration testing",
        "WiFi security assessment",
        "Network troubleshooting",
        "Security research"
      ],
      features: [
        "Monitor mode support",
        "WEP/WPA/WPA2 cracking",
        "Packet injection",
        "Multiple attack vectors",
        "Cross-platform compatibility"
      ],
      installSteps: [
        "Install from repository: sudo apt install aircrack-ng",
        "Verify wireless adapter: airmon-ng",
        "Check for monitor mode support: iwconfig",
        "Test installation: aircrack-ng --help"
      ],
      basicUsage: [
        "Enable monitor mode: airmon-ng start [interface]",
        "Scan networks: airodump-ng [interface]mon",
        "Capture traffic: airodump-ng -c [channel] -w [file] [interface]mon",
        "Crack password: aircrack-ng -w [wordlist] [capture_file]"
      ],
      advancedExamples: [
        "WPS attack: reaver -i wlan0mon -b BSSID -vv",
        "Evil twin: airbase-ng -e 'FreeWiFi' -c 6 wlan0mon",
        "Replay attack: aireplay-ng -3 -b BSSID -h CLIENT wlan0mon",
        "Fragmentation: aireplay-ng -5 -b BSSID -h CLIENT wlan0mon"
      ],
      realWorldScenarios: [
        "Penetration Testing: Assess client's wireless network security during authorized testing",
        "Security Audit: Verify wireless security policies are properly implemented",
        "Incident Response: Investigate unauthorized wireless access points",
        "Research: Study wireless security mechanisms and vulnerabilities"
      ],
      troubleshooting: [
        "Monitor mode fails: Check adapter compatibility and driver support",
        "No packets captured: Ensure correct channel and proximity to target",
        "Injection not working: Verify adapter supports packet injection",
        "Permission denied: Run commands with sudo privileges"
      ],
      securityTips: [
        "Only test on networks you own or have explicit permission to test",
        "Use strong WPA2/WPA3 encryption with complex passwords",
        "Regularly monitor for unauthorized access points",
        "Keep wireless drivers and tools updated"
      ]
    },
    {
      id: "kismet",
      name: "Kismet",
      fullName: "Kismet Wireless Network Detector",
      description: "Wireless network detector, sniffer, and intrusion detection system",
      longDescription: "Kismet is a wireless network and device detector, sniffer, wardriving tool, and WIDS (wireless intrusion detection) framework.",
      category: "Wireless Security",
      difficulty: "Advanced",
      lastUpdated: "2024-01-18",
      officialSite: "https://www.kismetwireless.net",
      downloadUrl: "https://www.kismetwireless.net/code/",
      platform: "Cross-platform",
      license: "Open Source",
      icon: "📶",
      whatItIs: "A comprehensive wireless network detection and monitoring framework.",
      whatItsUsedFor: "Wireless network discovery, intrusion detection, wardriving, and wireless security monitoring.",
      howItWorks: "Passively monitors wireless networks without sending packets, detecting networks, devices, and potential security threats through traffic analysis.",
      commands: [
        "kismet -c wlan0",
        "kismet_server",
        "kismet_client",
        "kismet -t wireless_scan"
      ],
      results: [
        "Detected 15 wireless networks",
        "Found 23 wireless devices",
        "Identified 2 potential intrusions",
        "GPS coordinates logged for wardriving"
      ],
      useCases: [
        "Wireless intrusion detection",
        "Wardriving and site surveys",
        "Network discovery",
        "RF spectrum analysis"
      ],
      features: [
        "Passive monitoring",
        "Multiple protocol support",
        "GPS integration",
        "Web interface",
        "Plugin architecture"
      ],
      installSteps: [
        "Install dependencies: sudo apt install build-essential git",
        "Clone repository: git clone https://www.kismetwireless.net/git/kismet.git",
        "Configure: ./configure",
        "Compile and install: make && sudo make install"
      ],
      basicUsage: [
        "Start server: kismet_server",
        "Connect client: kismet_client",
        "Specify interface: kismet -c wlan0",
        "Web interface: http://localhost:2501"
      ],
      advancedExamples: [
        "Multiple interfaces: kismet -c wlan0,wlan1,wlan2",
        "Custom config: kismet -f /path/to/kismet.conf",
        "Remote capture: kismet -c tcp://192.168.1.100:3501",
        "Plugin loading: kismet --plugin-dir /path/to/plugins"
      ],
      realWorldScenarios: [
        "Security Monitoring: Continuous monitoring of corporate wireless environment",
        "Wardriving Survey: Mapping wireless networks in urban environments",
        "Incident Investigation: Detecting unauthorized wireless devices",
        "Compliance Auditing: Ensuring wireless policy compliance"
      ],
      troubleshooting: [
        "Interface errors: Ensure proper driver support and permissions",
        "No networks detected: Check antenna connectivity and positioning",
        "High CPU usage: Reduce monitoring interfaces or adjust filters",
        "Database issues: Check SQLite database permissions and disk space"
      ],
      securityTips: [
        "Use in monitor mode to avoid network disruption",
        "Implement proper access controls for Kismet data",
        "Regularly update to latest version for security patches",
        "Secure the web interface with strong authentication"
      ]
    }
  ],
  "web-application": [
    {
      id: "burp-suite",
      name: "Burp Suite",
      fullName: "Burp Suite Web Application Security Testing",
      description: "Integrated platform for web application security testing",
      longDescription: "Burp Suite is an integrated platform for performing security testing of web applications. Its various tools work seamlessly together to support the entire testing process.",
      category: "Web Application",
      difficulty: "Intermediate",
      lastUpdated: "2024-01-25",
      officialSite: "https://portswigger.net/burp",
      downloadUrl: "https://portswigger.net/burp/releases",
      platform: "Cross-platform",
      license: "Commercial",
      icon: "🕷️",
      whatItIs: "A comprehensive web application security testing platform with intercepting proxy and various security testing tools.",
      whatItsUsedFor: "Web application penetration testing, vulnerability discovery, manual testing, and automated scanning.",
      howItWorks: "Acts as an intercepting proxy between browser and web application, allowing analysis and manipulation of HTTP traffic to identify security vulnerabilities.",
      commands: [
        "java -jar burpsuite_community.jar",
        "java -Xmx2g -jar burpsuite_pro.jar",
        "burpsuite &",
        "java -jar burp.jar --config-file=project.json"
      ],
      results: [
        "HTTP request intercepted and modified",
        "SQL injection vulnerability detected",
        "XSS payload successfully executed",
        "Scanner found 15 security issues"
      ],
      useCases: [
        "Web application penetration testing",
        "Manual security testing",
        "Automated vulnerability scanning",
        "API security testing"
      ],
      features: [
        "Intercepting proxy",
        "Web vulnerability scanner",
        "Intruder attack tool",
        "Repeater for request manipulation",
        "Extensions marketplace"
      ],
      installSteps: [
        "Download from official website",
        "Install Java Runtime Environment (JRE) 11+",
        "Run installer or execute JAR file",
        "Configure browser proxy settings"
      ],
      basicUsage: [
        "Configure browser proxy: 127.0.0.1:8080",
        "Intercept requests in Proxy tab",
        "Send requests to Repeater for testing",
        "Use Intruder for automated attacks"
      ],
      advancedExamples: [
        "Custom extension: Load BApp store extensions for specialized testing",
        "Session handling: Configure complex authentication workflows",
        "Macro recording: Automate complex multi-step processes",
        "Collaborator: Use for out-of-band interaction testing"
      ],
      realWorldScenarios: [
        "E-commerce Testing: Comprehensive security assessment of online shopping platform",
        "API Security: Testing REST APIs for authentication and authorization flaws",
        "Session Management: Analyzing complex multi-user application workflows",
        "Payment Gateway: Security testing of financial transaction systems"
      ],
      troubleshooting: [
        "Proxy not working: Check browser proxy settings and certificate installation",
        "Performance issues: Increase Java heap size with -Xmx parameter",
        "SSL errors: Install Burp's CA certificate in browser",
        "Scanner not finding issues: Configure authentication and crawl settings"
      ],
      securityTips: [
        "Only test applications you own or have permission to test",
        "Use professional version for commercial assessments",
        "Keep Burp updated for latest vulnerability checks",
        "Properly scope testing to avoid testing unintended applications"
      ]
    },
    {
      id: "owasp-zap",
      name: "OWASP ZAP",
      fullName: "OWASP Zed Attack Proxy",
      description: "Free security testing proxy for web applications",
      longDescription: "OWASP ZAP is one of the world's most popular free security tools and is actively maintained by hundreds of international volunteers.",
      category: "Web Application",
      difficulty: "Beginner",
      lastUpdated: "2024-01-22",
      officialSite: "https://www.zaproxy.org",
      downloadUrl: "https://www.zaproxy.org/download/",
      platform: "Cross-platform",
      license: "Open Source",
      icon: "⚡",
      whatItIs: "A free, open-source web application security scanner and proxy.",
      whatItsUsedFor: "Web application security testing, vulnerability discovery, and security automation in CI/CD pipelines.",
      howItWorks: "Functions as an intercepting proxy and active/passive scanner to identify security vulnerabilities in web applications.",
      commands: [
        "zap.sh -daemon -port 8080",
        "zap-baseline.py -t http://example.com",
        "zap-full-scan.py -t http://example.com",
        "zap-api-scan.py -t http://api.example.com"
      ],
      results: [
        "Baseline scan completed: 5 alerts found",
        "SQL injection detected at login form",
        "Cross-site scripting vulnerability found",
        "Passive scan identified security headers missing"
      ],
      useCases: [
        "Automated security testing",
        "Manual penetration testing",
        "CI/CD integration",
        "Security education"
      ],
      features: [
        "Intercepting proxy",
        "Automated scanners",
        "Fuzzing capability",
        "REST API",
        "Docker support"
      ],
      installSteps: [
        "Download installer from zaproxy.org",
        "Install Java 8+ runtime",
        "Run installer or extract archive",
        "Configure browser proxy settings"
      ],
      basicUsage: [
        "Launch ZAP GUI or daemon mode",
        "Configure browser proxy: localhost:8080",
        "Browse target application to build site map",
        "Run active scan on discovered URLs"
      ],
      advancedExamples: [
        "Authenticated scanning: Configure authentication for protected areas",
        "Custom scripts: Write JavaScript for specialized testing",
        "API testing: Import OpenAPI definitions for API testing",
        "Docker scanning: docker run -t owasp/zap2docker-stable zap-baseline.py"
      ],
      realWorldScenarios: [
        "DevSecOps Integration: Automated security testing in CI/CD pipeline",
        "Bug Bounty: Quick automated scanning to identify potential vulnerabilities",
        "Security Training: Teaching web application security concepts",
        "Compliance Testing: Regular automated scans for security compliance"
      ],
      troubleshooting: [
        "Scanner not finding pages: Ensure proper spidering configuration",
        "False positives: Fine-tune scanner rules and add exclusions",
        "Performance issues: Adjust thread count and request delays",
        "Authentication issues: Verify session management configuration"
      ],
      securityTips: [
        "Always test in a safe, authorized environment",
        "Keep ZAP updated for latest security checks",
        "Review scan results carefully to avoid false positives",
        "Use authentication to test protected application areas"
      ]
    },
    {
      id: "sqlmap",
      name: "SQLMap",
      fullName: "SQLMap SQL Injection Testing Tool",
      description: "Automatic SQL injection and database takeover tool",
      longDescription: "SQLMap is an open source penetration testing tool that automates the process of detecting and exploiting SQL injection flaws and taking over database servers.",
      category: "Web Application",
      difficulty: "Advanced",
      lastUpdated: "2024-01-20",
      officialSite: "https://sqlmap.org",
      downloadUrl: "https://github.com/sqlmapproject/sqlmap",
      platform: "Cross-platform",
      license: "Open Source",
      icon: "💉",
      whatItIs: "An automated SQL injection detection and exploitation tool.",
      whatItsUsedFor: "Detecting and exploiting SQL injection vulnerabilities in web applications and database servers.",
      howItWorks: "Automates the process of detecting SQL injection flaws by testing various injection techniques and payloads against web application parameters.",
      commands: [
        "sqlmap -u 'http://example.com/page.php?id=1'",
        "sqlmap -r request.txt --dbs",
        "sqlmap -u URL --tables -D database",
        "sqlmap -u URL --dump -T table -D database"
      ],
      results: [
        "SQL injection found in parameter 'id'",
        "Available databases: information_schema, mysql, users",
        "Tables in 'users' database: admin, customers, orders",
        "Data dumped from 'admin' table: 50 entries extracted"
      ],
      useCases: [
        "SQL injection testing",
        "Database security assessment",
        "Penetration testing",
        "Security research"
      ],
      features: [
        "Multiple DBMS support",
        "Various injection techniques",
        "Database enumeration",
        "File system access",
        "Operating system takeover"
      ],
      installSteps: [
        "Clone repository: git clone https://github.com/sqlmapproject/sqlmap.git",
        "Install Python 3.x",
        "Navigate to directory: cd sqlmap",
        "Run: python sqlmap.py --help"
      ],
      basicUsage: [
        "Test URL: sqlmap -u [URL]",
        "Test POST request: sqlmap -r [request_file]",
        "List databases: sqlmap -u [URL] --dbs",
        "Dump table: sqlmap -u [URL] -D [db] -T [table] --dump"
      ],
      advancedExamples: [
        "Bypass WAF: sqlmap -u URL --tamper=space2comment,charencode",
        "OS shell: sqlmap -u URL --os-shell",
        "Custom payload: sqlmap -u URL --suffix=')' --prefix='('",
        "Batch mode: sqlmap -u URL --batch --smart"
      ],
      realWorldScenarios: [
        "Web App Pentest: Comprehensive SQL injection testing during security assessment",
        "Bug Bounty: Automated testing of large web applications for SQL injection",
        "Red Team Exercise: Database compromise during authorized security testing",
        "Vulnerability Research: Studying SQL injection in various database systems"
      ],
      troubleshooting: [
        "No injection found: Try different techniques with --technique parameter",
        "WAF blocking: Use tamper scripts or adjust request timing",
        "False positives: Use --string or --regexp for better detection",
        "Connection issues: Adjust --timeout and --retries parameters"
      ],
      securityTips: [
        "Only test on systems you own or have explicit permission to test",
        "Be cautious with data extraction to avoid damaging production systems",
        "Use --safe-url and --safe-freq to maintain session validity",
        "Always follow responsible disclosure when finding vulnerabilities"
      ]
    }
  ],
  "forensics": [
    {
      id: "autopsy",
      name: "Autopsy",
      fullName: "Autopsy Digital Forensics Platform",
      description: "Digital forensics platform and GUI for The Sleuth Kit",
      longDescription: "Autopsy is a digital forensics platform and graphical interface to The Sleuth Kit and other digital forensics tools. It provides a comprehensive suite of tools for investigating digital evidence.",
      category: "Forensics",
      difficulty: "Intermediate",
      lastUpdated: "2024-01-15",
      officialSite: "https://www.autopsy.com",
      downloadUrl: "https://www.autopsy.com/download/",
      platform: "Cross-platform",
      license: "Open Source",
      icon: "🔬",
      whatItIs: "A comprehensive digital forensics platform with graphical interface for investigating digital evidence.",
      whatItsUsedFor: "Digital forensics investigations, incident response, malware analysis, and legal evidence processing.",
      howItWorks: "Provides a unified interface for various forensics tools, automates evidence processing, and presents findings through an intuitive graphical interface.",
      commands: [
        "autopsy",
        "autopsy --nosplash",
        "./autopsy.exe",
        "java -jar autopsy.jar"
      ],
      results: [
        "Case created successfully",
        "Disk image processed: 500GB, 1.2M files",
        "Keyword search completed: 147 hits found",
        "Timeline analysis generated"
      ],
      useCases: [
        "Digital forensics investigations",
        "Incident response",
        "Legal evidence processing",
        "Malware analysis"
      ],
      features: [
        "Multi-format support",
        "Keyword searching",
        "Timeline analysis",
        "Hash calculation",
        "Registry analysis"
      ],
      installSteps: [
        "Download from official website",
        "Install Java Runtime Environment (JRE) 8+",
        "Run installer or extract archive",
        "Launch application and create first case"
      ],
      basicUsage: [
        "Create new case with Case > New Case",
        "Add data source (disk image, drive, files)",
        "Configure ingest modules for analysis",
        "Review results in various analysis views"
      ],
      advancedExamples: [
        "Timeline analysis: Tools > Create Timeline to analyze file activity",
        "Hash database: Configure NSRL database for known file filtering",
        "Keyword lists: Create custom keyword lists for targeted searches",
        "Export results: Generate comprehensive reports for legal proceedings"
      ],
      realWorldScenarios: [
        "Corporate Investigation: Analyzing employee computer for data theft evidence",
        "Law Enforcement: Processing seized digital devices for criminal investigation",
        "Incident Response: Examining compromised systems for attack vectors",
        "Litigation Support: Extracting relevant documents for legal proceedings"
      ],
      troubleshooting: [
        "Out of memory: Increase JVM heap size in configuration files",
        "Slow processing: Add more RAM or use solid-state drives",
        "Database errors: Check disk space and database connectivity",
        "Module failures: Verify dependencies and update to latest version"
      ],
      securityTips: [
        "Always work on forensic copies, never original evidence",
        "Maintain proper chain of custody documentation",
        "Use write blockers when acquiring evidence",
        "Keep detailed logs of all analysis activities"
      ]
    },
    {
      id: "volatility",
      name: "Volatility",
      fullName: "Volatility Memory Forensics Framework",
      description: "Advanced memory forensics framework for incident response and malware analysis",
      longDescription: "Volatility is an advanced memory forensics framework that provides a comprehensive collection of tools for the extraction of digital artifacts from volatile memory samples.",
      category: "Forensics",
      difficulty: "Advanced",
      lastUpdated: "2024-01-12",
      officialSite: "https://www.volatilityfoundation.org",
      downloadUrl: "https://github.com/volatilityfoundation/volatility3",
      platform: "Cross-platform",
      license: "Open Source",
      icon: "🧠",
      whatItIs: "A sophisticated memory forensics framework for analyzing volatile memory dumps.",
      whatItsUsedFor: "Memory analysis, malware detection, incident response, and advanced threat investigation.",
      howItWorks: "Analyzes memory dumps by parsing data structures, extracting processes, network connections, and other artifacts from RAM images.",
      commands: [
        "vol.py -f memory.dmp imageinfo",
        "vol.py -f memory.dmp --profile=Win7SP1x64 pslist",
        "vol.py -f memory.dmp --profile=Win7SP1x64 netscan",
        "vol.py -f memory.dmp --profile=Win7SP1x64 malfind"
      ],
      results: [
        "Profile detected: Win7SP1x64",
        "Found 67 processes in memory dump",
        "Network connections: 15 active, 3 suspicious",
        "Malware indicators found in process ID 1337"
      ],
      useCases: [
        "Memory forensics analysis",
        "Malware investigation",
        "Incident response",
        "Advanced persistent threat hunting"
      ],
      features: [
        "Multi-platform support",
        "Process analysis",
        "Network artifact extraction",
        "Registry parsing",
        "Malware detection"
      ],
      installSteps: [
        "Install Python 3.6+",
        "Clone repository: git clone https://github.com/volatilityfoundation/volatility3.git",
        "Install dependencies: pip install -r requirements.txt",
        "Test installation: python vol.py --help"
      ],
      basicUsage: [
        "Identify OS: vol.py -f [dump] windows.info",
        "List processes: vol.py -f [dump] windows.pslist",
        "Show network: vol.py -f [dump] windows.netscan",
        "Extract files: vol.py -f [dump] windows.dumpfiles"
      ],
      advancedExamples: [
        "Hunt for hooks: vol.py -f dump windows.ssdt",
        "Extract timeline: vol.py -f dump timeliner.Timeliner",
        "Memory diff: vol.py -f dump1 -g dump2 windows.pslist",
        "Custom plugin: vol.py -f dump --plugins=/path/to/plugins custom.plugin"
      ],
      realWorldScenarios: [
        "APT Investigation: Analyzing memory from compromised executive workstation",
        "Malware Analysis: Examining encrypted malware behavior in memory",
        "Data Breach: Investigating lateral movement through memory artifacts",
        "Zero-Day Research: Analyzing exploit behavior in controlled environment"
      ],
      troubleshooting: [
        "Profile detection fails: Try manual profile specification or update profiles",
        "Out of memory: Use 64-bit system with sufficient RAM",
        "Plugin errors: Ensure compatibility between Volatility and plugin versions",
        "Slow analysis: Use SSD storage and increase system memory"
      ],
      securityTips: [
        "Analyze memory dumps in isolated, air-gapped environments",
        "Use virtual machines for malware-infected memory analysis",
        "Maintain chain of custody for legal investigations",
        "Keep Volatility profiles updated for new operating systems"
      ]
    }
  ],
  "exploitation": [
    {
      id: "metasploit",
      name: "Metasploit",
      fullName: "Metasploit Framework",
      description: "Advanced penetration testing and exploitation framework",
      longDescription: "Metasploit is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development.",
      category: "Exploitation",
      difficulty: "Advanced",
      lastUpdated: "2024-01-28",
      officialSite: "https://www.metasploit.com",
      downloadUrl: "https://github.com/rapid7/metasploit-framework",
      platform: "Cross-platform",
      license: "Open Source",
      icon: "💥",
      whatItIs: "A comprehensive exploitation framework for penetration testing and security research.",
      whatItsUsedFor: "Penetration testing, vulnerability exploitation, security research, and red team operations.",
      howItWorks: "Provides a modular framework with exploits, payloads, encoders, and post-exploitation modules to test and compromise target systems.",
      commands: [
        "msfconsole",
        "search type:exploit platform:windows",
        "use exploit/windows/smb/ms17_010_eternalblue",
        "set RHOSTS 192.168.1.100"
      ],
      results: [
        "Metasploit console started",
        "Found 25 matching exploits",
        "Exploit module loaded successfully",
        "Meterpreter session 1 opened"
      ],
      useCases: [
        "Penetration testing",
        "Vulnerability exploitation",
        "Security research",
        "Red team exercises"
      ],
      features: [
        "2000+ exploits",
        "Meterpreter payloads",
        "Post-exploitation modules",
        "Auxiliary scanners",
        "Social engineering toolkit"
      ],
      installSteps: [
        "Install via package manager: sudo apt install metasploit-framework",
        "Or download installer from official website",
        "Initialize database: msfdb init",
        "Start console: msfconsole"
      ],
      basicUsage: [
        "Launch console: msfconsole",
        "Search exploits: search [keyword]",
        "Use exploit: use [exploit_path]",
        "Set options: set RHOSTS [target_ip]"
      ],
      advancedExamples: [
        "Multi-handler: use multi/handler, set payload windows/meterpreter/reverse_tcp",
        "Post exploitation: run post/windows/gather/hashdump",
        "Pivoting: route add 192.168.2.0 255.255.255.0 1",
        "Custom module: loadpath /path/to/custom/modules"
      ],
      realWorldScenarios: [
        "Penetration Test: Comprehensive security assessment of corporate network",
        "Red Team Exercise: Simulated attack against organization's defenses",
        "Vulnerability Validation: Confirming exploitability of discovered vulnerabilities",
        "Security Research: Developing proof-of-concept exploits for new vulnerabilities"
      ],
      troubleshooting: [
        "Database connection: Run msfdb reinit to reset database",
        "Module not found: Update with msfupdate command",
        "Payload generation fails: Check architecture and platform compatibility",
        "Session dies quickly: Use migrate command to move to stable process"
      ],
      securityTips: [
        "Only use in authorized testing environments",
        "Keep framework updated for latest exploits and patches",
        "Use encrypted communications for sensitive operations",
        "Document all activities for compliance and reporting"
      ]
    }
  ],
  "mobile-security": [
    {
      id: "mobsf",
      name: "MobSF",
      fullName: "Mobile Security Framework",
      description: "Automated mobile application security testing framework",
      longDescription: "Mobile Security Framework (MobSF) is an automated, all-in-one mobile application security testing framework capable of performing static and dynamic analysis.",
      category: "Mobile Security",
      difficulty: "Intermediate",
      lastUpdated: "2024-01-20",
      officialSite: "https://mobsf.github.io/docs/",
      downloadUrl: "https://github.com/MobSF/Mobile-Security-Framework-MobSF",
      platform: "Cross-platform",
      license: "Open Source",
      icon: "📱",
      whatItIs: "A comprehensive mobile application security testing framework supporting static and dynamic analysis.",
      whatItsUsedFor: "Mobile app security testing, vulnerability assessment, malware analysis, and compliance checking.",
      howItWorks: "Automatically analyzes mobile applications through static code analysis, dynamic runtime analysis, and web API testing to identify security vulnerabilities.",
      commands: [
        "python manage.py runserver",
        "docker run -it -p 8000:8000 opensecurity/mobsf:latest",
        "./run.sh",
        "python manage.py help"
      ],
      results: [
        "Static analysis completed: 15 high-risk issues found",
        "Dynamic analysis session started",
        "API testing discovered 3 authentication flaws",
        "Malware scan: No malicious behavior detected"
      ],
      useCases: [
        "Mobile application security testing",
        "DevSecOps integration",
        "Malware analysis",
        "Compliance verification"
      ],
      features: [
        "Static code analysis",
        "Dynamic analysis",
        "API testing",
        "Malware detection",
        "Report generation"
      ],
      installSteps: [
        "Install Python 3.7+ and dependencies",
        "Clone repository: git clone https://github.com/MobSF/Mobile-Security-Framework-MobSF.git",
        "Navigate to directory: cd Mobile-Security-Framework-MobSF",
        "Install requirements: pip install -r requirements.txt"
      ],
      basicUsage: [
        "Start server: python manage.py runserver",
        "Open browser: http://localhost:8000",
        "Upload mobile app (APK/IPA)",
        "Review security analysis results"
      ],
      advancedExamples: [
        "CI/CD integration: Use REST API for automated testing",
        "Custom rules: Add organization-specific security checks",
        "Dynamic testing: Connect real device or emulator for runtime analysis",
        "Bulk scanning: Process multiple applications in batch mode"
      ],
      realWorldScenarios: [
        "App Store Security: Pre-publication security verification for mobile apps",
        "Enterprise Mobility: Security assessment of corporate mobile applications",
        "Malware Research: Analysis of suspicious mobile applications",
        "Compliance Audit: OWASP MASVS compliance verification"
      ],
      troubleshooting: [
        "Upload fails: Check file size limits and supported formats",
        "Analysis errors: Verify app permissions and dependencies",
        "Dynamic analysis issues: Ensure emulator/device connectivity",
        "Performance problems: Allocate more system resources"
      ],
      securityTips: [
        "Test applications in isolated environment",
        "Keep MobSF updated for latest security checks",
        "Review false positives carefully in results",
        "Integrate into SDLC for continuous security testing"
      ]
    },
    {
      id: "frida",
      name: "Frida",
      fullName: "Frida Dynamic Instrumentation Toolkit",
      description: "Dynamic instrumentation toolkit for developers and reverse engineers",
      longDescription: "Frida is a dynamic instrumentation toolkit for developers, reverse-engineers, and security researchers. It allows you to inject your own scripts into black box processes.",
      category: "Mobile Security",
      difficulty: "Advanced",
      lastUpdated: "2024-01-22",
      officialSite: "https://frida.re",
      downloadUrl: "https://github.com/frida/frida/releases",
      platform: "Cross-platform",
      license: "Open Source",
      icon: "🔧",
      whatItIs: "A dynamic instrumentation framework for runtime manipulation and analysis of applications.",
      whatItsUsedFor: "Runtime security analysis, reverse engineering, malware analysis, and application behavior modification.",
      howItWorks: "Injects JavaScript engines into target processes, allowing real-time hooking, tracing, and modification of application behavior.",
      commands: [
        "frida -U -l script.js com.example.app",
        "frida-ps -U",
        "frida-trace -U -i '*crypto*' com.example.app",
        "frida-ls-devices"
      ],
      results: [
        "Attached to process: com.example.app (PID: 1337)",
        "Hook installed on crypto function",
        "Intercepted 25 function calls",
        "Memory dump extracted successfully"
      ],
      useCases: [
        "Runtime application analysis",
        "API hooking and tracing",
        "Malware behavior analysis",
        "Security research"
      ],
      features: [
        "Cross-platform support",
        "JavaScript injection",
        "Function hooking",
        "Memory manipulation",
        "Protocol analysis"
      ],
      installSteps: [
        "Install Python 3.6+",
        "Install Frida: pip install frida-tools",
        "For mobile: Install frida-server on target device",
        "Verify installation: frida --version"
      ],
      basicUsage: [
        "List processes: frida-ps -U",
        "Attach to app: frida -U [package_name]",
        "Load script: frida -U -l script.js [package_name]",
        "Trace functions: frida-trace -U -i 'recv*' [package_name]"
      ],
      advancedExamples: [
        "SSL pinning bypass: Hook certificate validation functions",
        "Method tracing: Trace all methods in specific Java classes",
        "Memory scanning: Search for specific patterns in process memory",
        "Protocol analysis: Intercept and modify network communications"
      ],
      realWorldScenarios: [
        "iOS App Analysis: Bypassing jailbreak detection and runtime protections",
        "Android Malware: Analyzing malicious app behavior in controlled environment",
        "API Security: Testing mobile app backend communication security",
        "Vulnerability Research: Finding memory corruption bugs through runtime analysis"
      ],
      troubleshooting: [
        "Connection fails: Check device connectivity and frida-server version",
        "Script errors: Debug JavaScript syntax and API usage",
        "Process crashes: Add exception handling and careful memory access",
        "Performance issues: Optimize hook placement and reduce overhead"
      ],
      securityTips: [
        "Use on test devices only - never on production systems",
        "Keep frida-server updated for security and compatibility",
        "Be cautious with memory manipulation to avoid crashes",
        "Use proper exception handling in instrumentation scripts"
      ]
    }
  ],
  "password-attacks": [
    {
      id: "john-the-ripper",
      name: "John the Ripper",
      fullName: "John the Ripper Password Cracker",
      description: "Fast password cracker for various password hash types",
      longDescription: "John the Ripper is a fast password cracker, currently available for many flavors of Unix, Windows, DOS, BeOS, and OpenVMS. Its primary purpose is to detect weak Unix passwords.",
      category: "Password Attacks",
      difficulty: "Intermediate",
      lastUpdated: "2024-01-18",
      officialSite: "https://www.openwall.com/john/",
      downloadUrl: "https://github.com/openwall/john",
      platform: "Cross-platform",
      license: "Open Source",
      icon: "🔓",
      whatItIs: "A powerful password cracking tool supporting multiple hash formats and attack methods.",
      whatItsUsedFor: "Password security auditing, hash cracking, penetration testing, and security research.",
      howItWorks: "Uses various attack methods including dictionary attacks, brute force, and hybrid attacks to crack password hashes.",
      commands: [
        "john --wordlist=passwords.txt hashes.txt",
        "john --incremental hashes.txt",
        "john --show hashes.txt",
        "john --format=NT hashes.txt"
      ],
      results: [
        "Loaded 100 password hashes",
        "Password cracked: admin123 (admin)",
        "Session completed: 15 passwords cracked",
        "Remaining time: 2 days, 14 hours"
      ],
      useCases: [
        "Password strength auditing",
        "Hash cracking",
        "Penetration testing",
        "Digital forensics"
      ],
      features: [
        "Multiple hash formats",
        "Dictionary attacks",
        "Brute force attacks",
        "Rule-based attacks",
        "GPU acceleration"
      ],
      installSteps: [
        "Install from repository: sudo apt install john",
        "Or compile from source: git clone https://github.com/openwall/john",
        "Configure: cd john/src && make",
        "Test installation: john --test"
      ],
      basicUsage: [
        "Dictionary attack: john --wordlist=[wordlist] [hashfile]",
        "Brute force: john --incremental [hashfile]",
        "Show cracked: john --show [hashfile]",
        "Specify format: john --format=[format] [hashfile]"
      ],
      advancedExamples: [
        "Custom rules: john --wordlist=dict.txt --rules=custom hashes.txt",
        "Distributed cracking: john --node=1/4 --wordlist=dict.txt hashes.txt",
        "Session resume: john --restore=mysession",
        "Markov mode: john --markov hashes.txt"
      ],
      realWorldScenarios: [
        "Corporate Audit: Testing password strength across organization's user accounts",
        "Incident Response: Cracking passwords from compromised password dumps",
        "Penetration Test: Validating password policies during security assessment",
        "Digital Forensics: Recovering passwords from seized computer systems"
      ],
      troubleshooting: [
        "No hashes loaded: Check hash format and file structure",
        "Slow performance: Use GPU acceleration or distributed cracking",
        "Memory issues: Adjust settings for large wordlists",
        "Format not recognized: Specify correct hash format manually"
      ],
      securityTips: [
        "Only crack hashes you own or have permission to test",
        "Use strong, unique passwords to defend against cracking",
        "Implement proper password policies and complexity requirements",
        "Monitor for weak passwords proactively in your organization"
      ]
    },
    {
      id: "hashcat",
      name: "Hashcat",
      fullName: "Hashcat Advanced Password Recovery",
      description: "World's fastest and most advanced password recovery utility",
      longDescription: "Hashcat is the world's fastest and most advanced password recovery utility, supporting five unique modes of attack for over 300 highly-optimized hashing algorithms.",
      category: "Password Attacks",
      difficulty: "Advanced",
      lastUpdated: "2024-01-16",
      officialSite: "https://hashcat.net/hashcat/",
      downloadUrl: "https://github.com/hashcat/hashcat",
      platform: "Cross-platform",
      license: "Open Source",
      icon: "⚡",
      whatItIs: "An advanced password recovery utility with GPU acceleration and support for hundreds of hash types.",
      whatItsUsedFor: "High-speed password cracking, hash recovery, security auditing, and cryptographic research.",
      howItWorks: "Leverages GPU computational power and optimized algorithms to perform extremely fast password attacks against various hash types.",
      commands: [
        "hashcat -m 0 -a 0 hashes.txt wordlist.txt",
        "hashcat -m 1000 -a 3 hashes.txt ?u?l?l?l?l?d?d",
        "hashcat -m 22000 -a 0 capture.hc22000 wordlist.txt",
        "hashcat --show hashes.txt"
      ],
      results: [
        "Device #1: GeForce RTX 3080, 8704 MB",
        "Speed: 25.6 GH/s (MD5)",
        "Cracked password: P@ssw0rd123",
        "Session: 1000000 candidates tested"
      ],
      useCases: [
        "GPU-accelerated password cracking",
        "WiFi password recovery",
        "Hash analysis",
        "Security research"
      ],
      features: [
        "300+ hash algorithms",
        "GPU acceleration",
        "Multiple attack modes",
        "Rule-based attacks",
        "Distributed cracking"
      ],
      installSteps: [
        "Download binary from official website",
        "Install GPU drivers (CUDA/OpenCL)",
        "Extract archive and navigate to directory",
        "Test: ./hashcat -b"
      ],
      basicUsage: [
        "Dictionary: hashcat -m [mode] -a 0 [hash] [wordlist]",
        "Brute force: hashcat -m [mode] -a 3 [hash] [mask]",
        "Show cracked: hashcat --show [hash]",
        "Benchmark: hashcat -b"
      ],
      advancedExamples: [
        "Rule-based: hashcat -m 0 -a 0 hashes.txt wordlist.txt -r rules/best64.rule",
        "Combinator: hashcat -m 0 -a 1 hashes.txt wordlist1.txt wordlist2.txt",
        "Hybrid: hashcat -m 0 -a 6 hashes.txt wordlist.txt ?d?d",
        "Session: hashcat -m 0 -a 0 hashes.txt wordlist.txt --session=mysession"
      ],
      realWorldScenarios: [
        "WiFi Penetration: Cracking WPA2 handshakes captured during wireless assessment",
        "Digital Forensics: Recovering passwords from encrypted files in criminal investigation",
        "Red Team Exercise: Breaking password hashes obtained during simulated attack",
        "Security Research: Analyzing strength of various hashing algorithms"
      ],
      troubleshooting: [
        "GPU not detected: Install proper drivers and OpenCL/CUDA runtime",
        "Out of memory: Reduce keyspace or use distributed attack",
        "Slow speeds: Check GPU utilization and thermal throttling",
        "No candidates: Verify hash format and attack parameters"
      ],
      securityTips: [
        "Use strong, unique passwords that resist dictionary and brute force attacks",
        "Implement proper key derivation functions with sufficient iterations",
        "Monitor GPU temperatures during extended cracking sessions",
        "Only test on hashes you own or have explicit permission to crack"
      ]
    }
  ],
  "reverse-engineering": [
    {
      id: "radare2",
      name: "Radare2",
      fullName: "Radare2 Reverse Engineering Framework",
      description: "Unix-like reverse engineering framework and command-line toolset",
      longDescription: "Radare2 is a portable reversing framework that can disassemble, debug, analyze, manipulate and visualize binary files in multiple architectures and file formats.",
      category: "Reverse Engineering",
      difficulty: "Advanced",
      lastUpdated: "2024-01-14",
      officialSite: "https://rada.re/n/",
      downloadUrl: "https://github.com/radareorg/radare2",
      platform: "Cross-platform",
      license: "Open Source",
      icon: "🔍",
      whatItIs: "A comprehensive reverse engineering framework with disassembly, debugging, and analysis capabilities.",
      whatItsUsedFor: "Binary analysis, malware reverse engineering, exploit development, and security research.",
      howItWorks: "Provides a unified interface for analyzing binaries through disassembly, debugging, and various analysis tools accessible via command line.",
      commands: [
        "r2 binary_file",
        "r2 -d binary_file",
        "rabin2 -I binary_file",
        "r2 -A binary_file"
      ],
      results: [
        "Binary loaded at 0x08048000",
        "Analysis complete: 1247 functions found",
        "Entry point: 0x08048400",
        "Architecture: x86-64"
      ],
      useCases: [
        "Malware analysis",
        "Binary exploitation",
        "Firmware analysis",
        "Vulnerability research"
      ],
      features: [
        "Multi-architecture support",
        "Debugger integration",
        "Scripting capabilities",
        "Graph visualization",
        "Plugin system"
      ],
      installSteps: [
        "Clone repository: git clone https://github.com/radareorg/radare2",
        "Navigate: cd radare2",
        "Install: sys/install.sh",
        "Verify: r2 -v"
      ],
      basicUsage: [
        "Open binary: r2 [file]",
        "Auto-analyze: aa",
        "List functions: afl",
        "Disassemble: pdf @ main"
      ],
      advancedExamples: [
        "Debug session: r2 -d ./binary arg1 arg2",
        "Remote debugging: r2 -D gdb gdb://localhost:1234",
        "Scripting: r2 -i script.r2 binary",
        "Visual mode: VV @ main (enter visual graph mode)"
      ],
      realWorldScenarios: [
        "Malware Analysis: Reverse engineering sophisticated malware to understand behavior",
        "Exploit Development: Analyzing binaries to identify and exploit vulnerabilities",
        "Firmware Security: Analyzing IoT device firmware for security flaws",
        "CTF Challenges: Solving reverse engineering challenges in competitions"
      ],
      troubleshooting: [
        "Binary not loading: Check file format and architecture support",
        "Analysis incomplete: Try different analysis depth levels",
        "Debugging issues: Verify debugger permissions and target compatibility",
        "Performance problems: Use specific analysis commands instead of full auto-analysis"
      ],
      securityTips: [
        "Analyze unknown binaries in isolated environments",
        "Use virtual machines for malware analysis",
        "Keep r2 updated for latest architecture support",
        "Be cautious when debugging potentially malicious code"
      ]
    },
    {
      id: "ghidra",
      name: "Ghidra",
      fullName: "Ghidra Software Reverse Engineering Suite",
      description: "NSA's open-source software reverse engineering suite",
      longDescription: "Ghidra is a software reverse engineering (SRE) framework created and maintained by the National Security Agency Research Directorate.",
      category: "Reverse Engineering",
      difficulty: "Intermediate",
      lastUpdated: "2024-01-10",
      officialSite: "https://ghidra-sre.org",
      downloadUrl: "https://github.com/NationalSecurityAgency/ghidra/releases",
      platform: "Cross-platform",
      license: "Open Source",
      icon: "🔬",
      whatItIs: "A comprehensive software reverse engineering suite with advanced decompilation capabilities.",
      whatItsUsedFor: "Binary analysis, malware reverse engineering, vulnerability research, and software security assessment.",
      howItWorks: "Provides GUI-based binary analysis with automated decompilation, allowing analysts to understand program functionality through high-level code representation.",
      commands: [
        "./ghidraRun",
        "analyzeHeadless project_dir project_name -import binary",
        "./support/analyzeHeadless",
        "ghidra_headless"
      ],
      results: [
        "Project created successfully",
        "Binary imported and analyzed",
        "Decompilation completed: main() function",
        "1024 functions identified"
      ],
      useCases: [
        "Software reverse engineering",
        "Malware analysis",
        "Vulnerability research",
        "Binary auditing"
      ],
      features: [
        "Advanced decompiler",
        "Multi-platform support",
        "Collaborative analysis",
        "Scripting framework",
        "Version tracking"
      ],
      installSteps: [
        "Install Java JDK 11+",
        "Download Ghidra from official releases",
        "Extract archive: unzip ghidra_x.x.x_PUBLIC.zip",
        "Run: cd ghidra_x.x.x_PUBLIC && ./ghidraRun"
      ],
      basicUsage: [
        "Create new project: File > New Project",
        "Import binary: File > Import File",
        "Auto-analyze: Analysis > Auto Analyze",
        "View decompiled code in Decompile window"
      ],
      advancedExamples: [
        "Custom scripts: Write Java/Python scripts for automated analysis",
        "Collaborative analysis: Share projects across team members",
        "Version tracking: Compare different versions of same binary",
        "Extension development: Create custom analyzers and plugins"
      ],
      realWorldScenarios: [
        "Nation-State Malware: Analyzing advanced persistent threat (APT) malware samples",
        "Zero-Day Research: Discovering vulnerabilities in commercial software",
        "Firmware Analysis: Examining embedded system firmware for security flaws",
        "Legacy System Audit: Understanding undocumented legacy applications"
      ],
      troubleshooting: [
        "Java errors: Ensure compatible JDK version is installed",
        "Import failures: Check binary format and file corruption",
        "Performance issues: Increase JVM heap size in launch script",
        "Decompiler errors: Try different decompiler settings or manual analysis"
      ],
      securityTips: [
        "Run in isolated environment when analyzing malware",
        "Create regular project backups for important analysis work",
        "Use version control for collaborative projects",
        "Validate decompiled code accuracy through dynamic analysis"
      ]
    }
  ],
  "Social Engineering": [
    {
      id: "social-engineer-toolkit",
      name: "SET",
      fullName: "Social-Engineer Toolkit",
      description: "Framework for social engineering penetration testing",
      longDescription: "The Social-Engineer Toolkit is an open-source penetration testing framework designed for social engineering attacks and gathering information.",
      category: "Social Engineering",
      difficulty: "Intermediate",
      lastUpdated: "2024-01-25",
      officialSite: "https://www.trustedsec.com/tools/the-social-engineer-toolkit-set/",
      downloadUrl: "https://github.com/trustedsec/social-engineer-toolkit",
      platform: "Cross-platform",
      license: "Open Source",
      icon: "🎭",
      whatItIs: "A specialized framework for conducting social engineering attacks during penetration tests.",
      whatItsUsedFor: "Social engineering testing, phishing campaigns, awareness training, and human factor security assessment.",
      howItWorks: "Provides pre-built attack vectors and templates to test human vulnerabilities through various social engineering techniques.",
      commands: [
        "setoolkit",
        "se-toolkit",
        "python setoolkit.py",
        "./setoolkit"
      ],
      results: [
        "SET framework initialized",
        "Phishing email sent to 50 targets",
        "Credential harvester captured 12 passwords",
        "USB payload generated successfully"
      ],
      useCases: [
        "Social engineering testing",
        "Phishing awareness training",
        "Human factor assessment",
        "Security awareness validation"
      ],
      features: [
        "Phishing attack vectors",
        "Website cloning",
        "Mass mailer",
        "USB/DVD attacks",
        "Wireless access point attacks"
      ],
      installSteps: [
        "Clone repository: git clone https://github.com/trustedsec/social-engineer-toolkit.git",
        "Navigate to directory: cd social-engineer-toolkit",
        "Install dependencies: sudo python setup.py install",
        "Launch toolkit: sudo setoolkit"
      ],
      basicUsage: [
        "Launch SET: sudo setoolkit",
        "Select attack vector from main menu",
        "Configure phishing campaign",
        "Deploy and monitor results"
      ],
      advancedExamples: [
        "Create custom phishing templates",
        "Setup credential harvester with SSL",
        "Deploy USB/CD autorun payloads",
        "Combine with Metasploit for full exploitation"
      ],
      realWorldScenarios: [
        "Employee security awareness testing",
        "Red team social engineering assessments",
        "Phishing simulation campaigns",
        "Human vulnerability identification"
      ],
      troubleshooting: [
        "Run as root for full functionality",
        "Check firewall settings for web services",
        "Verify email server configuration",
        "Update framework regularly"
      ],
      securityTips: [
        "Only use in authorized testing environments",
        "Obtain proper written consent before testing",
        "Keep detailed logs of all activities",
        "Follow responsible disclosure practices"
      ]
    }
  ]
};

export function getCategoryData(category: string) {
  const categoryMap: Record<string, { title: string; description: string; tools: Tool[] }> = {
    "information-gathering": {
      title: "Information Gathering",
      description: "Network reconnaissance and target enumeration tools",
      tools: getToolsByCategory("Information Gathering")
    },
    "wireless-hacking": {
      title: "Wireless Hacking",
      description: "WiFi security testing and wireless penetration tools",
      tools: getToolsByCategory("Wireless Security")
    },
    "social-engineering": {
      title: "Social Engineering",
      description: "Phishing frameworks and social manipulation tools",
      tools: getToolsByCategory("Social Engineering")
    },
    "exploitation": {
      title: "Exploitation",
      description: "Vulnerability exploitation and payload generation",
      tools: getToolsByCategory("Exploitation")
    },
    "password-cracking": {
      title: "Password Cracking",
      description: "Hash cracking and password recovery utilities",
      tools: getToolsByCategory("Password Attacks")
    },
    "vulnerability-scanning": {
      title: "Vulnerability Scanning",
      description: "Automated security assessment and scanning tools",
      tools: getToolsByCategory("Vulnerability Analysis")
    },
    "forensics": {
      title: "Forensics",
      description: "Digital forensics and incident response tools",
      tools: getToolsByCategory("Forensics")
    },
    "web-assessment": {
      title: "Web Assessment",
      description: "Web application security testing frameworks",
      tools: getToolsByCategory("Web Application")
    }
  };

  return categoryMap[category] || { title: "Unknown Category", description: "Category not found", tools: [] };
}

export function getToolsByCategory(category: string): Tool[] {
  return toolsData[category] || [];
}

export function getAllTools(): Tool[] {
  return Object.values(toolsData).flat();
}

export function getToolById(id: string): Tool | undefined {
  return getAllTools().find(tool => tool.id === id);
}

export function searchTools(query: string): Tool[] {
  const allTools = getAllTools();
  const lowercaseQuery = query.toLowerCase();
  
  return allTools.filter(tool => 
    tool.name.toLowerCase().includes(lowercaseQuery) ||
    tool.description.toLowerCase().includes(lowercaseQuery) ||
    tool.category.toLowerCase().includes(lowercaseQuery)
  );
}