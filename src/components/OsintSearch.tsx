import { useState } from 'react';
import { Search, User, Mail, Loader2, Shield } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { PrivacyNote } from './DisclaimerBanner';
import { validateUsername, validateEmail } from '@/lib/osint/search';

interface OsintSearchProps {
  onSearch: (username: string, email?: string) => void;
  isSearching: boolean;
}

export function OsintSearch({ onSearch, isSearching }: OsintSearchProps) {
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [errors, setErrors] = useState<{ username?: string; email?: string }>({});

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    
    // Validate inputs
    const usernameValidation = validateUsername(username);
    const emailValidation = validateEmail(email);
    
    const newErrors: { username?: string; email?: string } = {};
    
    if (!usernameValidation.valid) {
      newErrors.username = usernameValidation.error;
    }
    
    if (!emailValidation.valid) {
      newErrors.email = emailValidation.error;
    }
    
    setErrors(newErrors);
    
    if (usernameValidation.valid && emailValidation.valid) {
      onSearch(username.trim(), email.trim() || undefined);
    }
  };

  return (
    <Card className="border-border bg-card/50 backdrop-blur">
      <CardHeader className="text-center pb-4">
        <div className="flex items-center justify-center gap-2 mb-2">
          <Shield className="h-8 w-8 text-primary" />
          <CardTitle className="text-2xl font-bold">OSINT Search</CardTitle>
        </div>
        <CardDescription className="text-muted-foreground max-w-lg mx-auto">
          Analyze potential public exposure by searching where a username may appear across platforms. 
          Results are probabilistic inferences based on public data only.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="username" className="flex items-center gap-2">
              <User className="h-4 w-4" />
              Username <span className="text-destructive">*</span>
            </Label>
            <Input
              id="username"
              type="text"
              placeholder="Enter username to search"
              value={username}
              onChange={(e) => {
                setUsername(e.target.value);
                if (errors.username) {
                  setErrors(prev => ({ ...prev, username: undefined }));
                }
              }}
              disabled={isSearching}
              className={errors.username ? 'border-destructive' : ''}
              maxLength={50}
            />
            {errors.username && (
              <p className="text-xs text-destructive">{errors.username}</p>
            )}
          </div>

          <div className="space-y-2">
            <Label htmlFor="email" className="flex items-center gap-2">
              <Mail className="h-4 w-4" />
              Email <span className="text-muted-foreground text-xs">(optional, hashed locally)</span>
            </Label>
            <Input
              id="email"
              type="email"
              placeholder="Optional: email for correlation analysis"
              value={email}
              onChange={(e) => {
                setEmail(e.target.value);
                if (errors.email) {
                  setErrors(prev => ({ ...prev, email: undefined }));
                }
              }}
              disabled={isSearching}
              className={errors.email ? 'border-destructive' : ''}
            />
            {errors.email && (
              <p className="text-xs text-destructive">{errors.email}</p>
            )}
            <p className="text-xs text-muted-foreground">
              Email is hashed using SHA-256 locally and never stored or transmitted.
            </p>
          </div>

          <Button 
            type="submit" 
            className="w-full" 
            size="lg"
            disabled={isSearching || !username.trim()}
          >
            {isSearching ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin" />
                Searching...
              </>
            ) : (
              <>
                <Search className="h-4 w-4" />
                Search Public Profiles
              </>
            )}
          </Button>
        </form>

        <div className="mt-6">
          <PrivacyNote />
        </div>
      </CardContent>
    </Card>
  );
}
