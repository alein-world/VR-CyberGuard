import { ExternalLink, AlertCircle } from 'lucide-react';
import { Card, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { SearchResult } from '@/lib/osint/search';
import { getConfidenceBadgeClass } from '@/lib/osint/scoring';

interface ResultCardProps {
  result: SearchResult;
}

export function ResultCard({ result }: ResultCardProps) {
  const { platform, profileUrl, scoring, status } = result;
  
  const confidenceLabel = scoring.confidence.charAt(0).toUpperCase() + scoring.confidence.slice(1);
  const badgeClass = getConfidenceBadgeClass(scoring.confidence);

  return (
    <Card className="border-border bg-card/50 backdrop-blur hover:bg-card/70 transition-colors">
      <CardContent className="p-4">
        <div className="flex items-start justify-between gap-4">
          <div className="flex items-start gap-3 flex-1 min-w-0">
            <div className="text-2xl flex-shrink-0">{platform.icon}</div>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <h3 className="font-semibold text-foreground">{platform.name}</h3>
                <Badge variant="outline" className={`text-xs ${badgeClass}`}>
                  {confidenceLabel} Confidence
                </Badge>
                <Badge variant="outline" className="text-xs text-muted-foreground">
                  {platform.category}
                </Badge>
              </div>
              
              <p className="text-sm text-muted-foreground mt-1">
                {platform.description}
              </p>

              <div className="mt-3 p-2 bg-muted/50 rounded-md">
                <div className="flex items-start gap-2">
                  <AlertCircle className="h-4 w-4 text-muted-foreground flex-shrink-0 mt-0.5" />
                  <div className="text-xs text-muted-foreground">
                    <span className="font-medium">
                      {status === 'possible' ? 'Possible match' : 'May be associated'}:
                    </span>{' '}
                    {scoring.explanation}
                  </div>
                </div>
              </div>

              <div className="mt-2 flex items-center gap-2 text-xs text-muted-foreground">
                <span>Score: {scoring.score}/100</span>
                <span>•</span>
                <span className="truncate">{profileUrl}</span>
              </div>
            </div>
          </div>

          <Button
            variant="outline"
            size="sm"
            className="flex-shrink-0"
            onClick={() => window.open(profileUrl, '_blank', 'noopener,noreferrer')}
          >
            <ExternalLink className="h-4 w-4" />
            View
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

export function ResultsSkeleton() {
  return (
    <div className="space-y-3">
      {[1, 2, 3].map((i) => (
        <Card key={i} className="border-border bg-card/50">
          <CardContent className="p-4">
            <div className="flex items-start gap-3">
              <div className="w-8 h-8 bg-muted rounded animate-pulse" />
              <div className="flex-1 space-y-2">
                <div className="h-5 bg-muted rounded w-1/4 animate-pulse" />
                <div className="h-4 bg-muted rounded w-1/2 animate-pulse" />
                <div className="h-12 bg-muted rounded animate-pulse" />
              </div>
            </div>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}
