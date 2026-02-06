import { Loader2 } from 'lucide-react';
import { Progress } from '@/components/ui/progress';
import { SearchProgress as SearchProgressType } from '@/lib/osint/search';

interface SearchProgressProps {
  progress: SearchProgressType;
}

export function SearchProgress({ progress }: SearchProgressProps) {
  const percentage = Math.round((progress.current / progress.total) * 100);

  return (
    <div className="space-y-3 p-4 bg-muted/30 rounded-lg border border-border">
      <div className="flex items-center justify-between text-sm">
        <div className="flex items-center gap-2">
          <Loader2 className="h-4 w-4 animate-spin text-primary" />
          <span className="text-muted-foreground">Checking platforms...</span>
        </div>
        <span className="text-muted-foreground">
          {progress.current} / {progress.total}
        </span>
      </div>
      
      <Progress value={percentage} className="h-2" />
      
      <div className="text-xs text-muted-foreground text-center">
        Currently checking: <span className="text-foreground">{progress.currentPlatform}</span>
      </div>
    </div>
  );
}
