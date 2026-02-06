import { useMemo } from 'react';
import { BarChart3, Filter } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { SearchResult } from '@/lib/osint/search';
import { ResultCard } from './ResultCard';
import { DisclaimerBanner, OptOutNote } from './DisclaimerBanner';
import { ConfidenceLevel } from '@/lib/osint/scoring';

interface SearchResultsProps {
  results: SearchResult[];
  searchedUsername: string;
}

export function SearchResults({ results, searchedUsername }: SearchResultsProps) {
  const stats = useMemo(() => {
    const byConfidence = results.reduce((acc, r) => {
      acc[r.scoring.confidence] = (acc[r.scoring.confidence] || 0) + 1;
      return acc;
    }, {} as Record<ConfidenceLevel, number>);

    const byCategory = results.reduce((acc, r) => {
      acc[r.platform.category] = (acc[r.platform.category] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    return { byConfidence, byCategory };
  }, [results]);

  const highConfidence = results.filter(r => r.scoring.confidence === 'high');
  const mediumConfidence = results.filter(r => r.scoring.confidence === 'medium');
  const lowConfidence = results.filter(r => r.scoring.confidence === 'low');

  if (results.length === 0) {
    return (
      <Card className="border-border bg-card/50">
        <CardContent className="p-8 text-center">
          <p className="text-muted-foreground">
            No potential matches found for username "<span className="text-foreground font-medium">{searchedUsername}</span>".
          </p>
          <p className="text-sm text-muted-foreground mt-2">
            This could mean the username is not commonly used on public platforms, or profiles are set to private.
          </p>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-6">
      <DisclaimerBanner />

      {/* Stats Overview */}
      <Card className="border-border bg-card/50">
        <CardHeader className="pb-3">
          <CardTitle className="text-lg flex items-center gap-2">
            <BarChart3 className="h-5 w-5" />
            Results Overview for "{searchedUsername}"
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="text-center p-3 bg-muted/50 rounded-lg">
              <div className="text-2xl font-bold text-foreground">{results.length}</div>
              <div className="text-xs text-muted-foreground">Total Possible</div>
            </div>
            <div className="text-center p-3 bg-amber-500/10 rounded-lg border border-amber-500/20">
              <div className="text-2xl font-bold text-amber-500">{stats.byConfidence.high || 0}</div>
              <div className="text-xs text-muted-foreground">High Confidence</div>
            </div>
            <div className="text-center p-3 bg-blue-500/10 rounded-lg border border-blue-500/20">
              <div className="text-2xl font-bold text-blue-500">{stats.byConfidence.medium || 0}</div>
              <div className="text-xs text-muted-foreground">Medium Confidence</div>
            </div>
            <div className="text-center p-3 bg-muted/50 rounded-lg">
              <div className="text-2xl font-bold text-muted-foreground">{stats.byConfidence.low || 0}</div>
              <div className="text-xs text-muted-foreground">Low Confidence</div>
            </div>
          </div>

          {/* Category breakdown */}
          <div className="mt-4 flex flex-wrap gap-2">
            {Object.entries(stats.byCategory).map(([category, count]) => (
              <Badge key={category} variant="outline" className="text-xs">
                {category}: {count}
              </Badge>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Results Tabs */}
      <Tabs defaultValue="all" className="w-full">
        <TabsList className="grid w-full grid-cols-4">
          <TabsTrigger value="all" className="text-xs sm:text-sm">
            All ({results.length})
          </TabsTrigger>
          <TabsTrigger value="high" className="text-xs sm:text-sm">
            High ({highConfidence.length})
          </TabsTrigger>
          <TabsTrigger value="medium" className="text-xs sm:text-sm">
            Medium ({mediumConfidence.length})
          </TabsTrigger>
          <TabsTrigger value="low" className="text-xs sm:text-sm">
            Low ({lowConfidence.length})
          </TabsTrigger>
        </TabsList>

        <TabsContent value="all" className="mt-4 space-y-3">
          {results.map((result, index) => (
            <ResultCard key={`${result.platform.id}-${index}`} result={result} />
          ))}
        </TabsContent>

        <TabsContent value="high" className="mt-4 space-y-3">
          {highConfidence.length > 0 ? (
            highConfidence.map((result, index) => (
              <ResultCard key={`${result.platform.id}-${index}`} result={result} />
            ))
          ) : (
            <EmptyTabMessage confidence="high" />
          )}
        </TabsContent>

        <TabsContent value="medium" className="mt-4 space-y-3">
          {mediumConfidence.length > 0 ? (
            mediumConfidence.map((result, index) => (
              <ResultCard key={`${result.platform.id}-${index}`} result={result} />
            ))
          ) : (
            <EmptyTabMessage confidence="medium" />
          )}
        </TabsContent>

        <TabsContent value="low" className="mt-4 space-y-3">
          {lowConfidence.length > 0 ? (
            lowConfidence.map((result, index) => (
              <ResultCard key={`${result.platform.id}-${index}`} result={result} />
            ))
          ) : (
            <EmptyTabMessage confidence="low" />
          )}
        </TabsContent>
      </Tabs>

      <OptOutNote />
    </div>
  );
}

function EmptyTabMessage({ confidence }: { confidence: ConfidenceLevel }) {
  return (
    <Card className="border-border bg-card/50">
      <CardContent className="p-6 text-center text-muted-foreground">
        No {confidence} confidence results found.
      </CardContent>
    </Card>
  );
}
