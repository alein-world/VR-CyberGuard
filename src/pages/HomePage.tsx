import { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { LoadingBar } from "@/components/LoadingBar";
import { 
  Search, 
  Wifi, 
  Shield, 
  Zap, 
  Lock, 
  Bug, 
  Fingerprint, 
  Globe,
  ArrowRight,
  Users
} from "lucide-react";
import heroImage from "@/assets/hero-hacker.jpg";

export default function HomePage() {
  const [isLoading, setIsLoading] = useState(false);
  const [userIP, setUserIP] = useState<string>("");
  const [currentTime, setCurrentTime] = useState<string>("");

  useEffect(() => {
    // Capture user's IP address
    const fetchUserIP = async () => {
      try {
        const response = await fetch('https://api.ipify.org?format=json');
        const data = await response.json();
        setUserIP(data.ip);
      } catch (error) {
        console.error('Failed to fetch IP:', error);
        setUserIP('Unable to detect');
      }
    };
    
    fetchUserIP();
  }, []);

  useEffect(() => {
    // Update time every second
    const updateTime = () => {
      const now = new Date();
      setCurrentTime(now.toLocaleTimeString('en-US', { 
        hour12: false,
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
      }));
    };
    
    updateTime(); // Initial call
    const timer = setInterval(updateTime, 1000);
    
    return () => clearInterval(timer);
  }, []);

  const categories = [
    {
      title: "Information Gathering",
      description: "Network reconnaissance and target enumeration tools",
      icon: Search,
      href: "/category/information-gathering",
      tools: 12,
      difficulty: "Beginner",
      color: "text-cyber-green"
    },
    {
      title: "Wireless Hacking",
      description: "WiFi security testing and wireless penetration tools",
      icon: Wifi,
      href: "/category/wireless-hacking",
      tools: 8,
      difficulty: "Intermediate",
      color: "text-cyber-blue"
    },
    {
      title: "Social Engineering",
      description: "Phishing frameworks and social manipulation tools",
      icon: Users,
      href: "/category/social-engineering",
      tools: 6,
      difficulty: "Advanced",
      color: "text-cyber-red"
    },
    {
      title: "Exploitation",
      description: "Vulnerability exploitation and payload generation",
      icon: Zap,
      href: "/category/exploitation",
      tools: 15,
      difficulty: "Advanced",
      color: "text-cyber-green"
    },
    {
      title: "Password Cracking",
      description: "Hash cracking and password recovery utilities",
      icon: Lock,
      href: "/category/password-cracking",
      tools: 10,
      difficulty: "Intermediate",
      color: "text-cyber-blue"
    },
    {
      title: "Vulnerability Scanning",
      description: "Automated security assessment and scanning tools",
      icon: Bug,
      href: "/category/vulnerability-scanning",
      tools: 9,
      difficulty: "Beginner",
      color: "text-cyber-red"
    },
    {
      title: "Forensics",
      description: "Digital forensics and incident response tools",
      icon: Fingerprint,
      href: "/category/forensics",
      tools: 7,
      difficulty: "Advanced",
      color: "text-cyber-green"
    },
    {
      title: "Web Assessment",
      description: "Web application security testing frameworks",
      icon: Globe,
      href: "/category/web-assessment",
      tools: 11,
      difficulty: "Intermediate",
      color: "text-cyber-blue"
    }
  ];

  const handleCategoryClick = () => {
    setIsLoading(true);
    setTimeout(() => setIsLoading(false), 2000);
  };

  const getDifficultyColor = (difficulty: string) => {
    switch (difficulty) {
      case "Beginner": return "bg-cyber-green/20 text-cyber-green";
      case "Intermediate": return "bg-cyber-blue/20 text-cyber-blue";
      case "Advanced": return "bg-cyber-red/20 text-cyber-red";
      default: return "bg-muted/20 text-muted-foreground";
    }
  };

  return (
    <div className="min-h-screen">
      <LoadingBar isLoading={isLoading} onComplete={() => setIsLoading(false)} />
      
      {/* Hero Section */}
      <section className="relative overflow-hidden cyber-grid">
        <div className="absolute inset-0 bg-gradient-to-b from-background/50 to-background"></div>
        <div 
          className="absolute inset-0 bg-cover bg-center opacity-20"
          style={{ backgroundImage: `url(${heroImage})` }}
        ></div>
        
        <div className="relative container mx-auto px-4 py-24 lg:py-32">
          <div className="max-w-4xl mx-auto text-center">
            <h1 className="font-orbitron text-4xl lg:text-6xl font-bold mb-6 matrix-text">
              VR-Cyber Guard
            </h1>
            <p className="text-xl lg:text-2xl text-muted-foreground mb-8">
              Explore the most powerful cybersecurity tools, categorized for professionals, 
              students, and enthusiasts. Interactive simulations and comprehensive tutorials.
            </p>
            
            <div className="flex flex-col sm:flex-row gap-4 justify-center items-center">
              <Button 
                variant="neon" 
                size="xl"
                onClick={() => document.getElementById('categories')?.scrollIntoView({ behavior: 'smooth' })}
              >
                <Shield className="mr-2 h-5 w-5" />
                Explore Tools Arsenal
              </Button>
              <Button 
                variant="outline" 
                size="xl"
                onClick={() => document.getElementById('documentation')?.scrollIntoView({ behavior: 'smooth' })}
              >
                View Documentation
                <ArrowRight className="ml-2 h-5 w-5" />
              </Button>
            </div>
          </div>
        </div>
      </section>

      {/* Statistics Section */}
      <section className="py-16 bg-card/50">
        <div className="container mx-auto px-4">
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-8">
            <div className="text-center">
              <div className="text-3xl lg:text-4xl font-orbitron font-bold text-cyber-green mb-2">78+</div>
              <div className="text-muted-foreground">Security Tools</div>
            </div>
            <div className="text-center">
              <div className="text-3xl lg:text-4xl font-orbitron font-bold text-cyber-blue mb-2">8</div>
              <div className="text-muted-foreground">Categories</div>
            </div>
            <div className="text-center">
              <div className="text-3xl lg:text-4xl font-orbitron font-bold text-cyber-red mb-2">100%</div>
              <div className="text-muted-foreground">Interactive</div>
            </div>
            <div className="text-center">
              <div className="text-3xl lg:text-4xl font-orbitron font-bold text-cyber-green mb-2">24/7</div>
              <div className="text-muted-foreground">Available</div>
            </div>
          </div>
          
          {/* User IP and Time Display */}
          {(userIP || currentTime) && (
            <div className="mt-8 text-center">
              <div className="flex flex-col sm:flex-row gap-4 justify-center items-center">
                {userIP && (
                  <div className="inline-flex items-center px-4 py-2 bg-card/80 border border-border/50 rounded-lg backdrop-blur-sm">
                    <Globe className="h-4 w-4 text-cyber-blue mr-2" />
                    <span className="text-sm text-muted-foreground">Your IP: </span>
                    <span className="text-sm font-mono text-cyber-green ml-1">{userIP}</span>
                  </div>
                )}
                {currentTime && (
                  <div className="inline-flex items-center px-4 py-2 bg-card/80 border border-border/50 rounded-lg backdrop-blur-sm">
                    <svg className="h-4 w-4 text-cyber-red mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                    <span className="text-sm text-muted-foreground">System Time: </span>
                    <span className="text-sm font-mono text-cyber-red ml-1">{currentTime}</span>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </section>

      {/* Categories Section */}
      <section id="categories" className="py-16">
        <div className="container mx-auto px-4">
          <div className="text-center mb-12">
            <h2 className="font-orbitron text-3xl lg:text-4xl font-bold mb-4">
              Cybersecurity Arsenal
            </h2>
            <p className="text-lg text-muted-foreground max-w-2xl mx-auto">
              Choose your category and explore professional-grade security tools with 
              interactive simulations and real-world usage examples.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            {categories.map((category) => {
              const IconComponent = category.icon;
              return (
                <Link
                  key={category.title}
                  to={category.href}
                  onClick={handleCategoryClick}
                  className="group"
                >
                  <Card className="h-full hover-scale neon-glow transition-all duration-300 bg-card/80 backdrop-blur-sm border-border/50 hover:border-primary/50">
                    <CardHeader className="pb-4">
                      <div className={`w-12 h-12 rounded-lg bg-primary/10 flex items-center justify-center mb-3 group-hover:bg-primary/20 transition-colors`}>
                        <IconComponent className={`h-6 w-6 ${category.color}`} />
                      </div>
                      <CardTitle className="font-orbitron text-lg group-hover:text-primary transition-colors">
                        {category.title}
                      </CardTitle>
                      <CardDescription className="text-sm">
                        {category.description}
                      </CardDescription>
                    </CardHeader>
                    <CardContent>
                      <div className="flex items-center justify-between text-sm">
                        <span className="text-muted-foreground">
                          {category.tools} tools
                        </span>
                        <span className={`px-2 py-1 rounded-full text-xs font-medium ${getDifficultyColor(category.difficulty)}`}>
                          {category.difficulty}
                        </span>
                      </div>
                    </CardContent>
                  </Card>
                </Link>
              );
            })}
          </div>
        </div>
      </section>

      {/* Documentation Section */}
      <section id="documentation" className="py-16 bg-card/30">
        <div className="container mx-auto px-4">
          <div className="text-center mb-12">
            <h2 className="font-orbitron text-3xl lg:text-4xl font-bold mb-4">
              Platform Documentation
            </h2>
            <p className="text-lg text-muted-foreground max-w-3xl mx-auto">
              Comprehensive guides, tutorials, and best practices for cybersecurity professionals
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
            <Card className="bg-card/80 backdrop-blur-sm border-border/50 hover:border-primary/50 transition-all duration-300">
              <CardHeader>
                <CardTitle className="font-orbitron flex items-center">
                  <Shield className="h-5 w-5 text-cyber-green mr-2" />
                  Getting Started
                </CardTitle>
                <CardDescription>
                  Essential guide for beginners entering cybersecurity
                </CardDescription>
              </CardHeader>
              <CardContent>
                <ul className="space-y-2 text-sm text-muted-foreground">
                  <li>• Setting up your testing environment</li>
                  <li>• Understanding tool categories</li>
                  <li>• Basic security concepts</li>
                  <li>• Legal and ethical guidelines</li>
                </ul>
              </CardContent>
            </Card>

            <Card className="bg-card/80 backdrop-blur-sm border-border/50 hover:border-primary/50 transition-all duration-300">
              <CardHeader>
                <CardTitle className="font-orbitron flex items-center">
                  <Search className="h-5 w-5 text-cyber-blue mr-2" />
                  Tool Mastery
                </CardTitle>
                <CardDescription>
                  Advanced techniques and professional workflows
                </CardDescription>
              </CardHeader>
              <CardContent>
                <ul className="space-y-2 text-sm text-muted-foreground">
                  <li>• Advanced command combinations</li>
                  <li>• Automation and scripting</li>
                  <li>• Custom tool configurations</li>
                  <li>• Performance optimization</li>
                </ul>
              </CardContent>
            </Card>

            <Card className="bg-card/80 backdrop-blur-sm border-border/50 hover:border-primary/50 transition-all duration-300">
              <CardHeader>
                <CardTitle className="font-orbitron flex items-center">
                  <Bug className="h-5 w-5 text-cyber-red mr-2" />
                  Best Practices
                </CardTitle>
                <CardDescription>
                  Professional standards and security protocols
                </CardDescription>
              </CardHeader>
              <CardContent>
                <ul className="space-y-2 text-sm text-muted-foreground">
                  <li>• Responsible disclosure</li>
                  <li>• Documentation standards</li>
                  <li>• Risk assessment methods</li>
                  <li>• Compliance frameworks</li>
                </ul>
              </CardContent>
            </Card>
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-16 bg-gradient-to-r from-primary/10 to-secondary/10">
        <div className="container mx-auto px-4 text-center">
          <h2 className="font-orbitron text-2xl lg:text-3xl font-bold mb-4">
            Ready to Master Cybersecurity?
          </h2>
          <p className="text-lg text-muted-foreground mb-8 max-w-2xl mx-auto">
            Join thousands of security professionals using VR-Cyber Guard to stay ahead 
            of the latest threats and techniques.
          </p>
          <Button variant="cyber" size="xl">
            Start Your Journey
            <ArrowRight className="ml-2 h-5 w-5" />
          </Button>
        </div>
      </section>
    </div>
  );
}