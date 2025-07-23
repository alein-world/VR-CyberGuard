import React from 'react';
import { useParams } from 'react-router-dom';
import { toolsData, getToolById } from '@/data/toolsData';
import { Header } from '@/components/Header';
import { Badge } from '@/components/ui/badge';
import { Copy } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { useToast } from '@/hooks/use-toast';
import HashGenerator from '@/components/HashGenerator';

const ToolPage = () => {
  const { toolId } = useParams<{ toolId: string }>();
  const tool = getToolById(toolId || '');
  const { toast } = useToast();

  if (!tool) {
    return (
      <div className="min-h-screen bg-background">
        <Header />
        <main className="container mx-auto px-4 py-8">
          <div className="text-center">
            <h1 className="text-3xl font-bold mb-4">Tool Not Found</h1>
            <p className="text-muted-foreground">
              The requested tool could not be found.
            </p>
          </div>
        </main>
      </div>
    );
  }

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast({
      title: "Copied",
      description: "Command copied to clipboard"
    });
  };
  
  const renderSpecialTool = () => {
    switch (tool.id) {
      case 'hash-generator':
        return <HashGenerator />;
      default:
        return null;
    }
  };

  return (
    <div className="min-h-screen bg-background">
      <Header />
      
      <main className="container mx-auto px-4 py-8">
        <div className="mb-8">
          <h1 className="text-4xl font-bold">{tool.name}</h1>
          <p className="text-muted-foreground">{tool.description}</p>
          <Badge className="mt-2">{tool.category}</Badge>
        </div>

        <section className="mb-6">
          <h2 className="text-2xl font-semibold mb-2">Description</h2>
          <p className="text-muted-foreground">{tool.longDescription}</p>
        </section>

        {tool.commands && tool.commands.length > 0 && (
          <section className="mb-6">
            <h2 className="text-2xl font-semibold mb-2">Commands</h2>
            <ul className="space-y-2">
              {tool.commands.map((command, index) => (
                <li key={index} className="bg-card rounded-md p-4 relative">
                  <code className="text-sm font-mono">{command}</code>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="absolute top-2 right-2"
                    onClick={() => copyToClipboard(command)}
                  >
                    <Copy className="h-4 w-4" />
                  </Button>
                </li>
              ))}
            </ul>
          </section>
        )}

        {tool.useCases && tool.useCases.length > 0 && (
          <section className="mb-6">
            <h2 className="text-2xl font-semibold mb-2">Use Cases</h2>
            <ul className="list-disc list-inside text-muted-foreground">
              {tool.useCases.map((useCase, index) => (
                <li key={index}>{useCase}</li>
              ))}
            </ul>
          </section>
        )}

        {tool.installation && (
          <section className="mb-6">
            <h2 className="text-2xl font-semibold mb-2">Installation</h2>
            <div className="space-y-3">
              {tool.installation.linux && (
                <div>
                  <h3 className="font-semibold">Linux:</h3>
                  <code className="text-sm font-mono bg-card rounded-md p-2">{tool.installation.linux}</code>
                </div>
              )}
              {tool.installation.windows && (
                <div>
                  <h3 className="font-semibold">Windows:</h3>
                  <code className="text-sm font-mono bg-card rounded-md p-2">{tool.installation.windows}</code>
                </div>
              )}
              {tool.installation.mac && (
                <div>
                  <h3 className="font-semibold">Mac:</h3>
                  <code className="text-sm font-mono bg-card rounded-md p-2">{tool.installation.mac}</code>
                </div>
              )}
            </div>
          </section>
        )}

        {tool.examples && tool.examples.length > 0 && (
          <section className="mb-6">
            <h2 className="text-2xl font-semibold mb-2">Examples</h2>
            <div className="space-y-4">
              {tool.examples.map((example, index) => (
                <div key={index} className="bg-card rounded-md p-4">
                  <h3 className="font-semibold">Command:</h3>
                  <code className="text-sm font-mono">{example.command}</code>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="absolute top-2 right-2"
                    onClick={() => copyToClipboard(example.command)}
                  >
                    <Copy className="h-4 w-4" />
                  </Button>
                  <p className="mt-2 text-muted-foreground">
                    <span className="font-semibold">Description:</span> {example.description}
                  </p>
                </div>
              ))}
            </div>
          </section>
        )}
        
        {/* Special interactive tools */}
        {renderSpecialTool()}
      </main>
    </div>
  );
};

export default ToolPage;
