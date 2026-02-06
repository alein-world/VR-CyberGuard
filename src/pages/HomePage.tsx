import { useState } from 'react';
import { Shield, Eye, Lock, Globe } from 'lucide-react';
import { OsintSearch } from '@/components/OsintSearch';
import { SearchResults } from '@/components/SearchResults';
import { SearchProgress } from '@/components/SearchProgress';
import { DisclaimerBanner } from '@/components/DisclaimerBanner';
import { performSearch, SearchResult, SearchProgress as SearchProgressType } from '@/lib/osint/search';

export default function HomePage() {
  const [isSearching, setIsSearching] = useState(false);
  const [searchProgress, setSearchProgress] = useState<SearchProgressType | null>(null);
  const [results, setResults] = useState<SearchResult[] | null>(null);
  const [searchedUsername, setSearchedUsername] = useState('');

  const handleSearch = async (username: string, email?: string) => {
    setIsSearching(true);
    setResults(null);
    setSearchedUsername(username);
    setSearchProgress({ current: 0, total: 1, currentPlatform: 'Starting...' });

    try {
      const searchResults = await performSearch(username, email, (progress) => {
        setSearchProgress(progress);
      });
      setResults(searchResults);
    } catch (error) {
      console.error('Search error:', error);
    } finally {
      setIsSearching(false);
      setSearchProgress(null);
    }
  };

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="border-b border-border bg-card/50 backdrop-blur sticky top-0 z-50">
        <div className="container mx-auto px-4 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Shield className="h-6 w-6 text-primary" />
              <span className="font-bold text-lg">ExposureCheck</span>
            </div>
            <div className="text-xs text-muted-foreground">
              Personal OSINT Research Tool
            </div>
          </div>
        </div>
      </header>

      {/* Hero Section */}
      <section className="py-12 border-b border-border">
        <div className="container mx-auto px-4 text-center">
          <h1 className="text-3xl md:text-4xl font-bold mb-4">
            Public Exposure Analysis
          </h1>
          <p className="text-muted-foreground max-w-2xl mx-auto mb-6">
            Analyze where a username may appear across publicly accessible platforms. 
            This tool uses inference and probability to correlate public signals — 
            it does not confirm account ownership.
          </p>
          
          {/* Key Features */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 max-w-3xl mx-auto mt-8">
            <div className="flex items-center gap-3 p-3 rounded-lg bg-muted/30 border border-border">
              <Eye className="h-5 w-5 text-primary flex-shrink-0" />
              <div className="text-left">
                <div className="text-sm font-medium">Public Data Only</div>
                <div className="text-xs text-muted-foreground">No login endpoints accessed</div>
              </div>
            </div>
            <div className="flex items-center gap-3 p-3 rounded-lg bg-muted/30 border border-border">
              <Lock className="h-5 w-5 text-primary flex-shrink-0" />
              <div className="text-left">
                <div className="text-sm font-medium">Privacy First</div>
                <div className="text-xs text-muted-foreground">Email hashed locally</div>
              </div>
            </div>
            <div className="flex items-center gap-3 p-3 rounded-lg bg-muted/30 border border-border">
              <Globe className="h-5 w-5 text-primary flex-shrink-0" />
              <div className="text-left">
                <div className="text-sm font-medium">30+ Platforms</div>
                <div className="text-xs text-muted-foreground">Cross-platform correlation</div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Main Content */}
      <main className="container mx-auto px-4 py-8">
        <div className="max-w-3xl mx-auto space-y-8">
          {/* Search Form */}
          <OsintSearch onSearch={handleSearch} isSearching={isSearching} />

          {/* Search Progress */}
          {isSearching && searchProgress && (
            <SearchProgress progress={searchProgress} />
          )}

          {/* Results */}
          {!isSearching && results !== null && (
            <SearchResults results={results} searchedUsername={searchedUsername} />
          )}

          {/* Initial State - Before Search */}
          {!isSearching && results === null && (
            <div className="space-y-6">
              <DisclaimerBanner />
              
              <div className="text-center py-8 text-muted-foreground">
                <p className="text-sm">
                  Enter a username above to begin the analysis.
                </p>
              </div>
            </div>
          )}
        </div>
      </main>

      {/* Footer */}
      <footer className="border-t border-border py-6 mt-12">
        <div className="container mx-auto px-4 text-center text-xs text-muted-foreground">
          <p className="mb-2">
            <strong>For personal research use only.</strong> This tool does not confirm account ownership.
          </p>
          <p>
            Results are probabilistic inferences based on publicly available data. 
            No private APIs, login endpoints, or password-reset mechanisms are used.
          </p>
        </div>
      </footer>
    </div>
  );
}
