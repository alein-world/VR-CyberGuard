import { useParams, Link } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { 
  ArrowLeft, 
  ExternalLink, 
  Play, 
  Star,
  Clock,
  Shield,
  Terminal,
  Zap
} from "lucide-react";

export default function CategoryPage() {
  const { category } = useParams<{ category: string }>();

  // Sample tool data - in a real app this would come from an API
  const toolsData: Record<string, any> = {
    "information-gathering": {
      title: "Information Gathering",
      description: "Network reconnaissance and target enumeration tools for cybersecurity professionals",
      tools: [
        {
          id: "nmap",
          name: "Nmap",
          description: "Network discovery and security auditing utility",
          difficulty: "Beginner",
          rating: 4.9,
          category: "Network Scanner",
          lastUpdated: "2024-01-15",
          icon: "🔍"
        },
        {
          id: "masscan",
          name: "Masscan",
          description: "High-speed TCP port scanner",
          difficulty: "Intermediate",
          rating: 4.6,
          category: "Port Scanner", 
          lastUpdated: "2024-01-10",
          icon: "⚡"
        },
        {
          id: "recon-ng",
          name: "Recon-ng",
          description: "Web reconnaissance framework",
          difficulty: "Advanced",
          rating: 4.7,
          category: "Framework",
          lastUpdated: "2024-01-12",
          icon: "🌐"
        },
        {
          id: "theharvester",
          name: "theHarvester",
          description: "E-mail, subdomain and people names harvester",
          difficulty: "Beginner",
          rating: 4.5,
          category: "OSINT",
          lastUpdated: "2024-01-08",
          icon: "📧"
        }
      ]
    },
    "wireless-hacking": {
      title: "Wireless Hacking",
      description: "WiFi security testing and wireless penetration tools",
      tools: [
        {
          id: "aircrack-ng",
          name: "Aircrack-ng",
          description: "Complete suite of tools to assess WiFi network security",
          difficulty: "Intermediate",
          rating: 4.8,
          category: "WiFi Cracker",
          lastUpdated: "2024-01-14",
          icon: "📡"
        },
        {
          id: "kismet",
          name: "Kismet",
          description: "Wireless network detector and packet analyzer",
          difficulty: "Advanced",
          rating: 4.6,
          category: "Analyzer",
          lastUpdated: "2024-01-11",
          icon: "📊"
        }
      ]
    }
  };

  const categoryData = toolsData[category || ""] || {
    title: "Category Not Found",
    description: "The requested category does not exist.",
    tools: []
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

  return (
    <div className="min-h-screen cyber-grid">
      <div className="container mx-auto px-4 py-8">
        {/* Breadcrumb */}
        <div className="flex items-center space-x-2 mb-8">
          <Link 
            to="/" 
            className="flex items-center text-muted-foreground hover:text-primary transition-colors"
          >
            <ArrowLeft className="mr-2 h-4 w-4" />
            Back to Arsenal
          </Link>
        </div>

        {/* Category Header */}
        <div className="mb-12">
          <h1 className="font-orbitron text-3xl lg:text-4xl font-bold mb-4 matrix-text">
            {categoryData.title}
          </h1>
          <p className="text-lg text-muted-foreground max-w-3xl">
            {categoryData.description}
          </p>
          
          <div className="flex items-center space-x-4 mt-6">
            <Badge variant="outline" className="neon-glow">
              {categoryData.tools.length} Tools Available
            </Badge>
            <Badge variant="outline">
              Updated Daily
            </Badge>
          </div>
        </div>

        {/* Tools Grid */}
        {categoryData.tools.length > 0 ? (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {categoryData.tools.map((tool: any) => (
              <Card 
                key={tool.id} 
                className="hover-scale neon-glow bg-card/80 backdrop-blur-sm border-border/50 hover:border-primary/50 transition-all duration-300"
              >
                <CardHeader>
                  <div className="flex items-start justify-between">
                    <div className="flex items-center space-x-3">
                      <div className="text-2xl">{tool.icon}</div>
                      <div>
                        <CardTitle className="font-orbitron text-xl">
                          {tool.name}
                        </CardTitle>
                        <Badge 
                          variant="outline" 
                          className={`mt-1 ${getDifficultyColor(tool.difficulty)}`}
                        >
                          {tool.difficulty}
                        </Badge>
                      </div>
                    </div>
                    <div className="flex items-center space-x-1">
                      {renderStars(tool.rating)}
                      <span className="text-sm text-muted-foreground ml-2">
                        {tool.rating}
                      </span>
                    </div>
                  </div>
                </CardHeader>
                
                <CardContent>
                  <CardDescription className="mb-4 text-base">
                    {tool.description}
                  </CardDescription>
                  
                  <div className="flex items-center justify-between text-sm text-muted-foreground mb-4">
                    <div className="flex items-center space-x-4">
                      <span className="flex items-center">
                        <Shield className="mr-1 h-4 w-4" />
                        {tool.category}
                      </span>
                      <span className="flex items-center">
                        <Clock className="mr-1 h-4 w-4" />
                        {tool.lastUpdated}
                      </span>
                    </div>
                  </div>
                  
                  <div className="flex space-x-3">
                    <Link to={`/tool/${tool.id}`} className="flex-1">
                      <Button variant="cyber" className="w-full">
                        <Terminal className="mr-2 h-4 w-4" />
                        Launch Tool
                      </Button>
                    </Link>
                    <Button variant="outline" size="icon">
                      <ExternalLink className="h-4 w-4" />
                    </Button>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        ) : (
          <div className="text-center py-16">
            <div className="text-6xl mb-4">🚧</div>
            <h3 className="font-orbitron text-xl font-bold mb-2">Coming Soon</h3>
            <p className="text-muted-foreground">
              This category is under development. Check back soon for new tools!
            </p>
          </div>
        )}

        {/* Category Footer */}
        <div className="mt-16 text-center">
          <Card className="bg-card/50 backdrop-blur-sm border-border/30">
            <CardContent className="py-8">
              <h3 className="font-orbitron text-xl font-bold mb-4">
                Need a specific tool?
              </h3>
              <p className="text-muted-foreground mb-6">
                Can't find what you're looking for? Request new tools or suggest improvements.
              </p>
              <Button variant="outline">
                Request Tool Addition
              </Button>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}