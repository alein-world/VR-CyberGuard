export interface Tool {
  id: string;
  name: string;
  description: string;
  longDescription: string;
  category: string;
  difficulty?: string;
  lastUpdated?: string;
  icon?: string;
  commands?: string[];
  useCases?: string[];
  installation?: {
    linux?: string;
    windows?: string;
    mac?: string;
  };
  examples?: {
    command: string;
    description: string;
  }[];
}

export interface Category {
  name: string;
  description: string;
  icon: string;
  toolCount: number;
}

export interface CategoryData {
  title: string;
  description: string;
  tools: Tool[];
}