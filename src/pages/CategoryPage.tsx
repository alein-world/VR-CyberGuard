import { useParams, Link } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { getCategoryData } from "@/data/toolsData";
import { 
  ArrowLeft, 
  ExternalLink, 
  Clock,
  Shield,
  Terminal
} from "lucide-react";

export default function CategoryPage() {
  const { category } = useParams<{ category: string }>();

  const categoryData = getCategoryData(category || "");

  const getDifficultyColor = (difficulty: string) => {
    switch (difficulty) {
      case "Beginner": return "bg-cyber-green/20 text-cyber-green border-cyber-green/30";
      case "Intermediate": return "bg-cyber-blue/20 text-cyber-blue border-cyber-blue/30";
      case "Advanced": return "bg-cyber-red/20 text-cyber-red border-cyber-red/30";
      default: return "bg-muted/20 text-muted-foreground border-muted/30";
    }
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