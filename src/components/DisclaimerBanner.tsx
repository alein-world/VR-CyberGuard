import { AlertTriangle, Info } from 'lucide-react';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';

interface DisclaimerBannerProps {
  variant?: 'default' | 'compact';
}

export function DisclaimerBanner({ variant = 'default' }: DisclaimerBannerProps) {
  if (variant === 'compact') {
    return (
      <div className="flex items-center gap-2 text-xs text-muted-foreground bg-muted/50 px-3 py-2 rounded-md border border-border">
        <Info className="h-3 w-3 flex-shrink-0" />
        <span>
          Results are inferred from public data. Matches are probabilistic and may be inaccurate.
        </span>
      </div>
    );
  }

  return (
    <Alert className="bg-warning/10 border-warning/30">
      <AlertTriangle className="h-4 w-4 text-warning" />
      <AlertTitle className="text-warning">Important Disclaimer</AlertTitle>
      <AlertDescription className="text-muted-foreground">
        <p className="mb-2">
          Results are based on public information and historical data. Matches are <strong>inferred</strong> and <strong>not confirmed</strong>.
        </p>
        <ul className="list-disc list-inside text-sm space-y-1">
          <li>This tool does NOT confirm account ownership</li>
          <li>Results indicate where a username <em>may</em> appear publicly</li>
          <li>False positives are possible - different people may use similar usernames</li>
          <li>No private data or login endpoints are accessed</li>
        </ul>
      </AlertDescription>
    </Alert>
  );
}

export function PrivacyNote() {
  return (
    <div className="text-xs text-muted-foreground bg-muted/30 px-4 py-3 rounded-lg border border-border">
      <p className="font-medium mb-1">Privacy & Data Handling</p>
      <ul className="space-y-1">
        <li>• Email addresses are hashed locally and never stored or transmitted</li>
        <li>• No search data is logged or persisted</li>
        <li>• Only publicly accessible profile pages are checked</li>
        <li>• Rate limiting is applied to prevent abuse</li>
      </ul>
    </div>
  );
}

export function OptOutNote() {
  return (
    <div className="text-xs text-muted-foreground mt-4 p-3 border border-border rounded-lg">
      <p className="font-medium mb-1">Removal Request</p>
      <p>
        If you believe information about you is being displayed incorrectly, 
        this is a personal research tool and does not store any data. 
        Results are generated in real-time from public sources.
      </p>
    </div>
  );
}
