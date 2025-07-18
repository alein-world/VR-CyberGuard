import { useParams, Link } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { TerminalSimulation } from "@/components/TerminalSimulation";
import { 
  ArrowLeft, 
  ExternalLink, 
  Download, 
  Star,
  Clock,
  Shield,
  BookOpen,
  Code,
  Play,
  Info
} from "lucide-react";

export default function ToolPage() {
  const { toolId } = useParams<{ toolId: string }>();

  // Sample tool data - in a real app this would come from an API
  const toolsData: Record<string, any> = {
    "nmap": {
      name: "Nmap",
      fullName: "Network Mapper",
      description: "Nmap (Network Mapper) is a free and open-source network discovery and security auditing utility.",
      longDescription: "Nmap is used to discover hosts and services on a computer network by sending packets and analyzing the responses. It provides a number of features for probing computer networks, including host discovery and service and operating system detection.",
      category: "Information Gathering",
      difficulty: "Beginner",
      rating: 4.9,
      downloads: "10M+",
      lastUpdated: "2024-01-15",
      officialSite: "https://nmap.org",
      icon: "🔍",
      whatItIs: "A powerful network scanning tool used for network discovery and security auditing.",
      whatItsUsedFor: "Network administrators and security professionals use Nmap to identify what devices are running on their systems, discovering hosts that are available and the services they offer, finding open ports, and detecting security risks.",
      howItWorks: "Nmap sends specially crafted packets to the target host(s) and then analyzes their responses. Based on the responses, it can determine what services are running, what operating system is running, what type of device it is, and many other characteristics.",
      commands: [
        "nmap -sn 192.168.1.0/24",
        "nmap -A target.com", 
        "nmap -sS -O target.com"
      ],
      results: [
        "Host Discovery Complete: Found 12 active hosts",
        "Port Scan Complete: Open ports - 22, 80, 443, 8080",
        "OS Detection: Linux 3.2 - 4.9 (98% confidence)"
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
      ]
    },
    "aircrack-ng": {
      name: "Aircrack-ng",
      fullName: "Aircrack-ng Suite",
      description: "Complete suite of tools to assess WiFi network security.",
      longDescription: "Aircrack-ng is a complete suite of tools to assess WiFi network security. It focuses on different areas of WiFi security: monitoring, attacking, testing, and cracking.",
      category: "Wireless Hacking",
      difficulty: "Intermediate",
      rating: 4.8,
      downloads: "5M+",
      lastUpdated: "2024-01-14",
      officialSite: "https://aircrack-ng.org",
      icon: "📡",
      whatItIs: "A comprehensive WiFi network security assessment toolkit.",
      whatItsUsedFor: "Security professionals use Aircrack-ng to test the security of wireless networks, identify vulnerabilities, and assess WiFi encryption strength.",
      howItWorks: "The suite captures and analyzes wireless traffic, performs attacks on WiFi networks, and attempts to crack encryption keys using various techniques including dictionary attacks and brute force.",
      commands: [
        "airodump-ng wlan0mon",
        "aircrack-ng capture.cap -w wordlist.txt",
        "aireplay-ng -0 5 -a [BSSID] wlan0mon"
      ],
      results: [
        "Monitoring Mode Activated: Interface wlan0mon ready",
        "WPA Handshake Captured: 4-way handshake complete",
        "Key Found! Password: 'admin123' (took 2.3 minutes)"
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
      ]
    }
  };

  const tool = toolsData[toolId || ""] || {
    name: "Tool Not Found",
    description: "The requested tool does not exist.",
    category: "Unknown",
    difficulty: "Unknown"
  };

  const getDifficultyColor = (difficulty: string) => {
    switch (difficulty) {
      case "Beginner": return "bg-cyber-green/20 text-cyber-green border-cyber-green/30";
      case "Intermediate": return "bg-cyber-blue/20 text-cyber-blue border-cyber-blue/30";
      case "Advanced": return "bg-cyber-red/20 text-cyber-red border-cyber-red/30";
      default: return "bg-muted/20 text-muted-foreground border-muted/30";
    }
  };

  const renderStars = (rating: number) => {
    return Array.from({ length: 5 }, (_, i) => (
      <Star
        key={i}
        className={`h-4 w-4 ${
          i < Math.floor(rating) ? "text-yellow-400 fill-current" : "text-gray-300"
        }`}
      />
    ));
  };

  if (!toolsData[toolId || ""]) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center">
          <div className="text-6xl mb-4">❌</div>
          <h1 className="font-orbitron text-2xl font-bold mb-4">Tool Not Found</h1>
          <p className="text-muted-foreground mb-6">The requested tool does not exist.</p>
          <Link to="/">
            <Button variant="cyber">
              <ArrowLeft className="mr-2 h-4 w-4" />
              Back to Arsenal
            </Button>
          </Link>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen cyber-grid">
      <div className="container mx-auto px-4 py-8">
        {/* Breadcrumb */}
        <div className="flex items-center space-x-2 mb-8">
          <Link 
            to="/" 
            className="text-muted-foreground hover:text-primary transition-colors"
          >
            Arsenal
          </Link>
          <span className="text-muted-foreground">/</span>
          <Link 
            to={`/category/${tool.category?.toLowerCase().replace(/\s+/g, '-')}`}
            className="text-muted-foreground hover:text-primary transition-colors"
          >
            {tool.category}
          </Link>
          <span className="text-muted-foreground">/</span>
          <span className="text-primary">{tool.name}</span>
        </div>

        {/* Tool Header */}
        <div className="mb-8">
          <div className="flex items-start justify-between mb-6">
            <div className="flex items-center space-x-4">
              <div className="text-4xl">{tool.icon}</div>
              <div>
                <h1 className="font-orbitron text-3xl lg:text-4xl font-bold matrix-text">
                  {tool.name}
                </h1>
                <p className="text-xl text-muted-foreground">{tool.fullName}</p>
              </div>
            </div>
            
            <div className="flex space-x-3">
              <Button variant="cyber" size="lg">
                <Download className="mr-2 h-4 w-4" />
                Install Tool
              </Button>
              <Button variant="outline" size="lg">
                <ExternalLink className="mr-2 h-4 w-4" />
                Official Site
              </Button>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-4">
            <Badge 
              variant="outline" 
              className={`${getDifficultyColor(tool.difficulty)}`}
            >
              {tool.difficulty}
            </Badge>
            <div className="flex items-center space-x-1">
              {renderStars(tool.rating)}
              <span className="text-sm text-muted-foreground ml-2">
                {tool.rating} ({tool.downloads} downloads)
              </span>
            </div>
            <Badge variant="outline">
              <Clock className="mr-1 h-3 w-3" />
              Updated {tool.lastUpdated}
            </Badge>
          </div>
        </div>

        {/* Tool Content */}
        <Tabs defaultValue="overview" className="space-y-6">
          <TabsList className="grid w-full grid-cols-4 bg-card/50">
            <TabsTrigger value="overview" className="font-orbitron">
              <Info className="mr-2 h-4 w-4" />
              Overview
            </TabsTrigger>
            <TabsTrigger value="simulation" className="font-orbitron">
              <Play className="mr-2 h-4 w-4" />
              Simulation
            </TabsTrigger>
            <TabsTrigger value="commands" className="font-orbitron">
              <Code className="mr-2 h-4 w-4" />
              Commands
            </TabsTrigger>
            <TabsTrigger value="documentation" className="font-orbitron">
              <BookOpen className="mr-2 h-4 w-4" />
              Docs
            </TabsTrigger>
          </TabsList>

          <TabsContent value="overview" className="space-y-6">
            <Card className="bg-card/80 backdrop-blur-sm">
              <CardHeader>
                <CardTitle className="font-orbitron">What is {tool.name}?</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-lg mb-4">{tool.whatItIs}</p>
                <p className="text-muted-foreground">{tool.longDescription}</p>
              </CardContent>
            </Card>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <Card className="bg-card/80 backdrop-blur-sm">
                <CardHeader>
                  <CardTitle className="font-orbitron">What it's used for</CardTitle>
                </CardHeader>
                <CardContent>
                  <p className="mb-4">{tool.whatItsUsedFor}</p>
                  <h4 className="font-semibold mb-2">Common Use Cases:</h4>
                  <ul className="space-y-1">
                    {tool.useCases?.map((useCase: string, index: number) => (
                      <li key={index} className="flex items-center text-sm">
                        <Shield className="mr-2 h-3 w-3 text-cyber-green" />
                        {useCase}
                      </li>
                    ))}
                  </ul>
                </CardContent>
              </Card>

              <Card className="bg-card/80 backdrop-blur-sm">
                <CardHeader>
                  <CardTitle className="font-orbitron">How it works</CardTitle>
                </CardHeader>
                <CardContent>
                  <p className="mb-4">{tool.howItWorks}</p>
                  <h4 className="font-semibold mb-2">Key Features:</h4>
                  <ul className="space-y-1">
                    {tool.features?.map((feature: string, index: number) => (
                      <li key={index} className="flex items-center text-sm">
                        <Star className="mr-2 h-3 w-3 text-cyber-blue" />
                        {feature}
                      </li>
                    ))}
                  </ul>
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          <TabsContent value="simulation">
            <Card className="bg-card/80 backdrop-blur-sm">
              <CardHeader>
                <CardTitle className="font-orbitron">Interactive {tool.name} Simulation</CardTitle>
                <CardDescription>
                  Experience {tool.name} in action with our interactive terminal simulation. 
                  This is a safe environment that demonstrates the tool's capabilities without affecting real systems.
                </CardDescription>
              </CardHeader>
              <CardContent>
                <TerminalSimulation
                  toolName={tool.name}
                  commands={tool.commands || []}
                  results={tool.results || []}
                  onComplete={() => console.log("Simulation complete")}
                />
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="commands">
            <Card className="bg-card/80 backdrop-blur-sm">
              <CardHeader>
                <CardTitle className="font-orbitron">Command Examples</CardTitle>
                <CardDescription>
                  Common {tool.name} commands and their usage patterns
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {tool.commands?.map((command: string, index: number) => (
                    <div key={index} className="terminal rounded-lg p-4">
                      <div className="font-mono text-cyber-blue mb-1">
                        $ {command}
                      </div>
                      <div className="text-sm text-muted-foreground">
                        {tool.results?.[index] && `Expected output: ${tool.results[index]}`}
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="documentation">
            <Card className="bg-card/80 backdrop-blur-sm">
              <CardHeader>
                <CardTitle className="font-orbitron">Documentation & Resources</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <Button variant="outline" className="justify-start h-auto p-4">
                      <ExternalLink className="mr-3 h-5 w-5" />
                      <div className="text-left">
                        <div className="font-semibold">Official Documentation</div>
                        <div className="text-sm text-muted-foreground">Complete reference guide</div>
                      </div>
                    </Button>
                    
                    <Button variant="outline" className="justify-start h-auto p-4">
                      <BookOpen className="mr-3 h-5 w-5" />
                      <div className="text-left">
                        <div className="font-semibold">Tutorials & Guides</div>
                        <div className="text-sm text-muted-foreground">Step-by-step tutorials</div>
                      </div>
                    </Button>
                    
                    <Button variant="outline" className="justify-start h-auto p-4">
                      <Code className="mr-3 h-5 w-5" />
                      <div className="text-left">
                        <div className="font-semibold">Script Examples</div>
                        <div className="text-sm text-muted-foreground">Ready-to-use scripts</div>
                      </div>
                    </Button>
                    
                    <Button variant="outline" className="justify-start h-auto p-4">
                      <Shield className="mr-3 h-5 w-5" />
                      <div className="text-left">
                        <div className="font-semibold">Security Best Practices</div>
                        <div className="text-sm text-muted-foreground">Safe usage guidelines</div>
                      </div>
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
}