// Digital Garden note types and interfaces

export interface NoteFrontmatter {
  title?: string;
  created?: string;
  updated?: string;
  tags?: string[];
  dg_publish?: boolean;
  [key: string]: unknown;
}

export interface Note {
  slug: string;
  title: string;
  content: string;
  frontmatter: NoteFrontmatter;
  rawContent: string;
}

export interface NoteLink {
  target: string;
  alias?: string;
  exists: boolean;
}
