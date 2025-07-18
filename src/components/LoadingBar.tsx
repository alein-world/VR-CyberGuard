import { useEffect, useState } from "react";

interface LoadingBarProps {
  isLoading: boolean;
  duration?: number;
  onComplete?: () => void;
}

export const LoadingBar = ({ isLoading, duration = 2000, onComplete }: LoadingBarProps) => {
  const [progress, setProgress] = useState(0);

  useEffect(() => {
    if (!isLoading) {
      setProgress(0);
      return;
    }

    const interval = setInterval(() => {
      setProgress((prev) => {
        if (prev >= 100) {
          clearInterval(interval);
          onComplete?.();
          return 100;
        }
        return prev + (100 / (duration / 50));
      });
    }, 50);

    return () => clearInterval(interval);
  }, [isLoading, duration, onComplete]);

  if (!isLoading && progress === 0) return null;

  return (
    <div className="fixed top-0 left-0 right-0 z-50">
      <div className="h-1 bg-background/50">
        <div 
          className="h-full loading-bar transition-all duration-75 ease-out"
          style={{ width: `${progress}%` }}
        />
      </div>
      
      {/* Terminal-style loading text */}
      <div className="absolute top-4 left-1/2 transform -translate-x-1/2 terminal rounded-md px-4 py-2">
        <div className="flex items-center space-x-2">
          <div className="flex space-x-1">
            <div className="w-2 h-2 bg-cyber-green rounded-full animate-pulse"></div>
            <div className="w-2 h-2 bg-cyber-blue rounded-full animate-pulse" style={{ animationDelay: '0.2s' }}></div>
            <div className="w-2 h-2 bg-cyber-red rounded-full animate-pulse" style={{ animationDelay: '0.4s' }}></div>
          </div>
          <span className="text-sm font-mono">
            Initializing cyber protocols... {Math.round(progress)}%
          </span>
        </div>
      </div>
    </div>
  );
};