// Confidence scoring logic for OSINT results
// All results are probabilistic and labeled accordingly

export type ConfidenceLevel = 'low' | 'medium' | 'high';

export interface ScoreBreakdown {
  usernameMatch: number;
  profileFound: number;
  additionalSignals: number;
  total: number;
}

export interface ScoringResult {
  score: number;
  confidence: ConfidenceLevel;
  breakdown: ScoreBreakdown;
  explanation: string;
}

// Scoring weights
const WEIGHTS = {
  EXACT_USERNAME_MATCH: 40,
  PROFILE_PAGE_ACCESSIBLE: 30,
  ADDITIONAL_SIGNALS: 20,
  MULTIPLE_CORRELATIONS: 10
};

// Score thresholds for confidence levels
const THRESHOLDS = {
  LOW_MAX: 39,
  MEDIUM_MAX: 69
};

export function calculateConfidence(score: number): ConfidenceLevel {
  if (score <= THRESHOLDS.LOW_MAX) return 'low';
  if (score <= THRESHOLDS.MEDIUM_MAX) return 'medium';
  return 'high';
}

export function calculateScore(factors: {
  usernameMatches: boolean;
  profileAccessible: boolean;
  hasAdditionalSignals?: boolean;
  multipleCorrelations?: boolean;
}): ScoringResult {
  const breakdown: ScoreBreakdown = {
    usernameMatch: factors.usernameMatches ? WEIGHTS.EXACT_USERNAME_MATCH : 0,
    profileFound: factors.profileAccessible ? WEIGHTS.PROFILE_PAGE_ACCESSIBLE : 0,
    additionalSignals: factors.hasAdditionalSignals ? WEIGHTS.ADDITIONAL_SIGNALS : 0,
    total: 0
  };

  if (factors.multipleCorrelations) {
    breakdown.additionalSignals += WEIGHTS.MULTIPLE_CORRELATIONS;
  }

  breakdown.total = breakdown.usernameMatch + breakdown.profileFound + breakdown.additionalSignals;

  const confidence = calculateConfidence(breakdown.total);
  
  const explanation = generateExplanation(factors, confidence);

  return {
    score: breakdown.total,
    confidence,
    breakdown,
    explanation
  };
}

function generateExplanation(
  factors: {
    usernameMatches: boolean;
    profileAccessible: boolean;
    hasAdditionalSignals?: boolean;
    multipleCorrelations?: boolean;
  },
  confidence: ConfidenceLevel
): string {
  const parts: string[] = [];

  if (factors.usernameMatches) {
    parts.push('Username matches exactly');
  }

  if (factors.profileAccessible) {
    parts.push('Public profile page may exist');
  }

  if (factors.hasAdditionalSignals) {
    parts.push('Additional public signals detected');
  }

  if (factors.multipleCorrelations) {
    parts.push('Multiple correlating data points');
  }

  const explanation = parts.join('. ');
  
  const confidenceNote = confidence === 'high' 
    ? 'Strong correlation indicators present.'
    : confidence === 'medium'
    ? 'Moderate correlation indicators present.'
    : 'Limited correlation indicators.';

  return `${explanation}. ${confidenceNote}`;
}

export function getConfidenceColor(confidence: ConfidenceLevel): string {
  switch (confidence) {
    case 'high':
      return 'text-amber-500';
    case 'medium':
      return 'text-blue-500';
    case 'low':
      return 'text-muted-foreground';
  }
}

export function getConfidenceBadgeClass(confidence: ConfidenceLevel): string {
  switch (confidence) {
    case 'high':
      return 'bg-amber-500/20 text-amber-500 border-amber-500/30';
    case 'medium':
      return 'bg-blue-500/20 text-blue-500 border-blue-500/30';
    case 'low':
      return 'bg-muted text-muted-foreground border-border';
  }
}
