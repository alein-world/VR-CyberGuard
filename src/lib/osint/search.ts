// OSINT search logic
// IMPORTANT: This only checks publicly accessible profile URLs
// No login/signup/password-reset endpoint checking
// All results are probabilistic inferences

import { platforms, Platform, getProfileUrl } from './platforms';
import { calculateScore, ScoringResult } from './scoring';

export interface SearchResult {
  platform: Platform;
  profileUrl: string;
  scoring: ScoringResult;
  status: 'possible' | 'may_exist';
  timestamp: Date;
}

export interface SearchProgress {
  current: number;
  total: number;
  currentPlatform: string;
}

// Simple hash function for email (SHA-256 would be used in production)
// This is a basic implementation for demo purposes
export async function hashEmail(email: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(email.toLowerCase().trim());
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// Validate username input
export function validateUsername(username: string): { valid: boolean; error?: string } {
  if (!username || username.trim().length === 0) {
    return { valid: false, error: 'Username is required' };
  }

  if (username.length < 2) {
    return { valid: false, error: 'Username must be at least 2 characters' };
  }

  if (username.length > 50) {
    return { valid: false, error: 'Username must be less than 50 characters' };
  }

  // Basic sanitization - allow alphanumeric, underscores, hyphens, dots
  const validPattern = /^[a-zA-Z0-9_\-\.]+$/;
  if (!validPattern.test(username)) {
    return { valid: false, error: 'Username contains invalid characters' };
  }

  return { valid: true };
}

// Validate email if provided
export function validateEmail(email: string): { valid: boolean; error?: string } {
  if (!email || email.trim().length === 0) {
    return { valid: true }; // Email is optional
  }

  const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailPattern.test(email)) {
    return { valid: false, error: 'Invalid email format' };
  }

  return { valid: true };
}

// Main search function
// Note: In a real implementation, this would make actual HTTP requests
// to check if profile pages exist. For this demo, we simulate the process.
export async function performSearch(
  username: string,
  email?: string,
  onProgress?: (progress: SearchProgress) => void
): Promise<SearchResult[]> {
  const results: SearchResult[] = [];
  const normalizedUsername = username.toLowerCase().trim();

  // Hash email if provided (never store or log the actual email)
  let emailHash: string | undefined;
  if (email && email.trim()) {
    emailHash = await hashEmail(email);
    console.log('Email hashed locally (hash not logged for privacy)');
  }

  const totalPlatforms = platforms.length;

  for (let i = 0; i < platforms.length; i++) {
    const platform = platforms[i];
    
    // Report progress
    if (onProgress) {
      onProgress({
        current: i + 1,
        total: totalPlatforms,
        currentPlatform: platform.name
      });
    }

    // Simulate checking delay (in real implementation, this would be rate-limited API calls)
    await new Promise(resolve => setTimeout(resolve, 50 + Math.random() * 100));

    // Simulate profile existence check
    // In a real implementation, this would:
    // 1. Make a HEAD or GET request to the profile URL
    // 2. Check the response status
    // 3. NOT use any login/signup/reset endpoints
    const profileUrl = getProfileUrl(platform.id, normalizedUsername);
    
    // Simulate probabilistic results (in real implementation, based on actual HTTP responses)
    const simulatedExists = simulateProfileCheck(normalizedUsername, platform.id);
    
    if (simulatedExists) {
      const scoring = calculateScore({
        usernameMatches: true,
        profileAccessible: simulatedExists,
        hasAdditionalSignals: emailHash ? Math.random() > 0.7 : false,
        multipleCorrelations: Math.random() > 0.8
      });

      results.push({
        platform,
        profileUrl,
        scoring,
        status: scoring.confidence === 'high' ? 'possible' : 'may_exist',
        timestamp: new Date()
      });
    }
  }

  // Sort by confidence score descending
  results.sort((a, b) => b.scoring.score - a.scoring.score);

  return results;
}

// Simulate profile check (for demo purposes)
// In production, this would make actual HTTP requests to public profile pages
function simulateProfileCheck(username: string, platformId: string): boolean {
  // Create deterministic but varied results based on username
  const hash = simpleHash(username + platformId);
  
  // Popular platforms have higher chance of matches
  const popularPlatforms = ['github', 'twitter', 'reddit', 'instagram', 'linkedin'];
  const baseChance = popularPlatforms.includes(platformId) ? 0.4 : 0.25;
  
  // Longer usernames are less likely to be taken everywhere
  const lengthFactor = Math.max(0, 1 - (username.length / 20));
  
  const chance = baseChance + (lengthFactor * 0.1);
  
  return (hash % 100) / 100 < chance;
}

function simpleHash(str: string): number {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash;
  }
  return Math.abs(hash);
}
