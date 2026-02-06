// Platform definitions for public profile checking
// IMPORTANT: Only uses publicly accessible profile URLs - no login/signup endpoint checking

export interface Platform {
  id: string;
  name: string;
  icon: string;
  category: string;
  profileUrlPattern: string;
  description: string;
}

export const platforms: Platform[] = [
  // Social Media
  {
    id: 'github',
    name: 'GitHub',
    icon: '💻',
    category: 'Development',
    profileUrlPattern: 'https://github.com/{username}',
    description: 'Code hosting and collaboration platform'
  },
  {
    id: 'reddit',
    name: 'Reddit',
    icon: '🔴',
    category: 'Social',
    profileUrlPattern: 'https://www.reddit.com/user/{username}',
    description: 'Social news and discussion platform'
  },
  {
    id: 'twitter',
    name: 'X (Twitter)',
    icon: '𝕏',
    category: 'Social',
    profileUrlPattern: 'https://twitter.com/{username}',
    description: 'Microblogging and social networking'
  },
  {
    id: 'instagram',
    name: 'Instagram',
    icon: '📷',
    category: 'Social',
    profileUrlPattern: 'https://www.instagram.com/{username}',
    description: 'Photo and video sharing platform'
  },
  {
    id: 'tiktok',
    name: 'TikTok',
    icon: '🎵',
    category: 'Social',
    profileUrlPattern: 'https://www.tiktok.com/@{username}',
    description: 'Short-form video platform'
  },
  {
    id: 'youtube',
    name: 'YouTube',
    icon: '▶️',
    category: 'Media',
    profileUrlPattern: 'https://www.youtube.com/@{username}',
    description: 'Video sharing platform'
  },
  {
    id: 'twitch',
    name: 'Twitch',
    icon: '🎮',
    category: 'Media',
    profileUrlPattern: 'https://www.twitch.tv/{username}',
    description: 'Live streaming platform'
  },
  {
    id: 'linkedin',
    name: 'LinkedIn',
    icon: '💼',
    category: 'Professional',
    profileUrlPattern: 'https://www.linkedin.com/in/{username}',
    description: 'Professional networking platform'
  },
  {
    id: 'pinterest',
    name: 'Pinterest',
    icon: '📌',
    category: 'Social',
    profileUrlPattern: 'https://www.pinterest.com/{username}',
    description: 'Visual discovery and bookmarking'
  },
  {
    id: 'medium',
    name: 'Medium',
    icon: '📝',
    category: 'Blogging',
    profileUrlPattern: 'https://medium.com/@{username}',
    description: 'Online publishing platform'
  },
  {
    id: 'devto',
    name: 'DEV Community',
    icon: '👩‍💻',
    category: 'Development',
    profileUrlPattern: 'https://dev.to/{username}',
    description: 'Developer community platform'
  },
  {
    id: 'gitlab',
    name: 'GitLab',
    icon: '🦊',
    category: 'Development',
    profileUrlPattern: 'https://gitlab.com/{username}',
    description: 'DevOps and code hosting platform'
  },
  {
    id: 'bitbucket',
    name: 'Bitbucket',
    icon: '🪣',
    category: 'Development',
    profileUrlPattern: 'https://bitbucket.org/{username}',
    description: 'Git repository hosting'
  },
  {
    id: 'stackoverflow',
    name: 'Stack Overflow',
    icon: '📚',
    category: 'Development',
    profileUrlPattern: 'https://stackoverflow.com/users/{username}',
    description: 'Q&A for programmers'
  },
  {
    id: 'hackernews',
    name: 'Hacker News',
    icon: '🟧',
    category: 'Tech',
    profileUrlPattern: 'https://news.ycombinator.com/user?id={username}',
    description: 'Tech news and discussion'
  },
  {
    id: 'keybase',
    name: 'Keybase',
    icon: '🔐',
    category: 'Security',
    profileUrlPattern: 'https://keybase.io/{username}',
    description: 'Crypto-based identity verification'
  },
  {
    id: 'patreon',
    name: 'Patreon',
    icon: '🎨',
    category: 'Creator',
    profileUrlPattern: 'https://www.patreon.com/{username}',
    description: 'Creator subscription platform'
  },
  {
    id: 'spotify',
    name: 'Spotify',
    icon: '🎧',
    category: 'Media',
    profileUrlPattern: 'https://open.spotify.com/user/{username}',
    description: 'Music streaming platform'
  },
  {
    id: 'soundcloud',
    name: 'SoundCloud',
    icon: '🔊',
    category: 'Media',
    profileUrlPattern: 'https://soundcloud.com/{username}',
    description: 'Audio sharing platform'
  },
  {
    id: 'flickr',
    name: 'Flickr',
    icon: '📸',
    category: 'Media',
    profileUrlPattern: 'https://www.flickr.com/people/{username}',
    description: 'Photo sharing and hosting'
  },
  {
    id: 'behance',
    name: 'Behance',
    icon: '🎨',
    category: 'Creative',
    profileUrlPattern: 'https://www.behance.net/{username}',
    description: 'Creative portfolio platform'
  },
  {
    id: 'dribbble',
    name: 'Dribbble',
    icon: '🏀',
    category: 'Creative',
    profileUrlPattern: 'https://dribbble.com/{username}',
    description: 'Design portfolio platform'
  },
  {
    id: 'producthunt',
    name: 'Product Hunt',
    icon: '🚀',
    category: 'Tech',
    profileUrlPattern: 'https://www.producthunt.com/@{username}',
    description: 'Product discovery platform'
  },
  {
    id: 'mastodon',
    name: 'Mastodon',
    icon: '🐘',
    category: 'Social',
    profileUrlPattern: 'https://mastodon.social/@{username}',
    description: 'Decentralized social network'
  },
  {
    id: 'telegram',
    name: 'Telegram',
    icon: '✈️',
    category: 'Messaging',
    profileUrlPattern: 'https://t.me/{username}',
    description: 'Messaging platform'
  },
  {
    id: 'vimeo',
    name: 'Vimeo',
    icon: '🎬',
    category: 'Media',
    profileUrlPattern: 'https://vimeo.com/{username}',
    description: 'Video hosting platform'
  },
  {
    id: 'gravatar',
    name: 'Gravatar',
    icon: '👤',
    category: 'Identity',
    profileUrlPattern: 'https://gravatar.com/{username}',
    description: 'Globally recognized avatar'
  },
  {
    id: 'about_me',
    name: 'About.me',
    icon: '🪪',
    category: 'Identity',
    profileUrlPattern: 'https://about.me/{username}',
    description: 'Personal landing page'
  },
  {
    id: 'linktree',
    name: 'Linktree',
    icon: '🌳',
    category: 'Identity',
    profileUrlPattern: 'https://linktr.ee/{username}',
    description: 'Link aggregation service'
  },
  {
    id: 'cashapp',
    name: 'Cash App',
    icon: '💵',
    category: 'Finance',
    profileUrlPattern: 'https://cash.app/${username}',
    description: 'Mobile payment service'
  }
];

export function getProfileUrl(platformId: string, username: string): string {
  const platform = platforms.find(p => p.id === platformId);
  if (!platform) return '';
  return platform.profileUrlPattern.replace('{username}', username);
}

export function getCategorizedPlatforms(): Record<string, Platform[]> {
  return platforms.reduce((acc, platform) => {
    if (!acc[platform.category]) {
      acc[platform.category] = [];
    }
    acc[platform.category].push(platform);
    return acc;
  }, {} as Record<string, Platform[]>);
}
