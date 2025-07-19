import { useParams, Link } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { TerminalSimulation } from "@/components/TerminalSimulation";
import { getToolById } from "@/data/toolsData";
import { 
  ArrowLeft, 
  ExternalLink, 
  Download, 
  Clock,
  Shield,
  BookOpen,
  Code,
  Play,
  Info,
  Star
} from "lucide-react";

export default function ToolPage() {
  const { toolId } = useParams<{ toolId: string }>();

  const tool = getToolById(toolId || "");

  const getDifficultyColor = (difficulty: string) => {
    switch (difficulty) {
      case "Beginner": return "bg-cyber-green/20 text-cyber-green border-cyber-green/30";
      case "Intermediate": return "bg-cyber-blue/20 text-cyber-blue border-cyber-blue/30";
      case "Advanced": return "bg-cyber-red/20 text-cyber-red border-cyber-red/30";
      default: return "bg-muted/20 text-muted-foreground border-muted/30";
    }
  };

  if (!tool) {
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
            <div className="text-sm text-muted-foreground">
              Professional-grade security tool
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