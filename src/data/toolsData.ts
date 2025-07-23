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
    toolCount: 2
  },
  {
    name: "Network Security",
    description: "Network analysis and security tools",
    icon: "Shield",
    toolCount: 2
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
    }
  ],
  "network-security": [
    {
      id: "wireshark",
      name: "Wireshark",
      description: "Network protocol analyzer",
      longDescription: "Wireshark is the world's foremost and widely-used network protocol analyzer. It lets you see what's happening on your network at a microscopic level.",
      category: "Network Security",
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
    }
  ]
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

export const getToolsByCategory = (categoryName: string) => {
  console.log('Getting tools for category:', categoryName);
  
  // Map display names to data keys
  const categoryMap: { [key: string]: string } = {
    "Information Gathering": "information-gathering",
    "Cryptography": "cryptography",
    "Web Security": "web-security",
    "Network Security": "network-security"
  };
  
  const dataKey = categoryMap[categoryName];
  const tools = toolsData[dataKey as keyof typeof toolsData] || [];
  
  console.log('Found tools:', tools);
  return tools;
};

export const getAllTools = () => {
  return Object.values(toolsData).flat();
};

export const getToolById = (id: string) => {
  return getAllTools().find(tool => tool.id === id);
};
