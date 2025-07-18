import { useState, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Play, Square, Terminal as TerminalIcon } from "lucide-react";

interface TerminalSimulationProps {
  toolName: string;
  commands: string[];
  results: string[];
  onComplete?: () => void;
}

export const TerminalSimulation = ({ 
  toolName, 
  commands, 
  results, 
  onComplete 
}: TerminalSimulationProps) => {
  const [isRunning, setIsRunning] = useState(false);
  const [currentStep, setCurrentStep] = useState(0);
  const [displayText, setDisplayText] = useState<string[]>([]);
  const [isVisible, setIsVisible] = useState(false);

  const startSimulation = () => {
    setIsRunning(true);
    setIsVisible(true);
    setCurrentStep(0);
    setDisplayText([`[CYBER-GUARD] Initializing ${toolName}...`]);
  };

  const stopSimulation = () => {
    setIsRunning(false);
    setCurrentStep(0);
    setDisplayText([]);
  };

  useEffect(() => {
    if (!isRunning || currentStep >= commands.length + results.length) {
      if (isRunning) {
        setIsRunning(false);
        onComplete?.();
      }
      return;
    }

    const timer = setTimeout(() => {
      if (currentStep < commands.length) {
        // Show command
        setDisplayText(prev => [
          ...prev,
          `$ ${commands[currentStep]}`,
          "Processing..."
        ]);
      } else {
        // Show result
        const resultIndex = currentStep - commands.length;
        setDisplayText(prev => [
          ...prev.slice(0, -1), // Remove "Processing..."
          results[resultIndex]
        ]);
      }
      setCurrentStep(prev => prev + 1);
    }, 1500);

    return () => clearTimeout(timer);
  }, [isRunning, currentStep, commands, results, onComplete]);

  return (
    <div className="space-y-4">
      <div className="flex items-center space-x-2">
        <Button
          onClick={startSimulation}
          disabled={isRunning}
          variant="cyber"
          size="lg"
          className="relative overflow-hidden"
        >
          <Play className="mr-2 h-4 w-4" />
          Run {toolName} Simulation
        </Button>
        
        {isRunning && (
          <Button
            onClick={stopSimulation}
            variant="destructive"
            size="lg"
          >
            <Square className="mr-2 h-4 w-4" />
            Stop
          </Button>
        )}
      </div>

      {isVisible && (
        <div className="terminal rounded-lg p-6 min-h-[300px] max-h-[500px] overflow-y-auto font-mono text-sm">
          <div className="flex items-center mb-4 pb-2 border-b border-cyber-green/30">
            <TerminalIcon className="mr-2 h-4 w-4 text-cyber-green" />
            <span className="text-cyber-green font-bold">VR-Cyber Guard Terminal</span>
            <div className="ml-auto flex space-x-2">
              <div className="w-3 h-3 rounded-full bg-cyber-red"></div>
              <div className="w-3 h-3 rounded-full bg-yellow-500"></div>
              <div className="w-3 h-3 rounded-full bg-cyber-green"></div>
            </div>
          </div>
          
          <div className="space-y-2">
            {displayText.map((line, index) => (
              <div 
                key={index} 
                className={`${
                  line.startsWith('$') 
                    ? 'text-cyber-blue' 
                    : line.includes('SUCCESS') || line.includes('COMPLETE')
                    ? 'text-cyber-green'
                    : line.includes('ERROR') || line.includes('FAILED')
                    ? 'text-cyber-red'
                    : 'text-terminal-text'
                }`}
              >
                {line}
                {index === displayText.length - 1 && isRunning && (
                  <span className="ml-1 animate-pulse">|</span>
                )}
              </div>
            ))}
          </div>
          
          {isRunning && (
            <div className="mt-4 flex items-center space-x-2">
              <div className="loading-bar w-full h-2"></div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};