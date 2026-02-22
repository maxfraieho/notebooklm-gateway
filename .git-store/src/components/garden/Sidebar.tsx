import { useState } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { ChevronRight, ChevronDown, FileText, Folder, Home, Menu, X, Network, MessageSquare, Sprout } from 'lucide-react';
import { getFolderStructure, getHomeNote } from '@/lib/notes/noteLoader';
import { SearchBar } from './SearchBar';
import { LanguageSwitcher } from './LanguageSwitcher';
import { ThemeToggle } from './ThemeToggle';
import { useLocale } from '@/hooks/useLocale';
import { cn } from '@/lib/utils';

interface FolderInfo {
  name: string;
  path: string;
  notes: { slug: string; title: string; isHome: boolean }[];
  subfolders: FolderInfo[];
}

interface FolderItemProps {
  folder: FolderInfo;
  level?: number;
}

function FolderItem({ folder, level = 0 }: FolderItemProps) {
  const [isOpen, setIsOpen] = useState(true);
  const location = useLocation();
  
  const hasContent = folder.notes.length > 0 || folder.subfolders.length > 0;
  
  return (
    <div className="w-full">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className={cn(
          "w-full flex items-center gap-2 px-3 py-2 text-sm text-muted-foreground hover:text-foreground hover:bg-accent/50 rounded-md transition-all duration-200",
          "font-medium"
        )}
        style={{ paddingLeft: `${12 + level * 12}px` }}
      >
        {hasContent ? (
          isOpen ? (
            <ChevronDown className="w-4 h-4 flex-shrink-0 transition-transform duration-200" />
          ) : (
            <ChevronRight className="w-4 h-4 flex-shrink-0 transition-transform duration-200" />
          )
        ) : (
          <span className="w-4" />
        )}
        <Folder className="w-4 h-4 flex-shrink-0 text-muted-foreground transition-colors duration-200" />
        <span className="truncate">{folder.name}</span>
      </button>
      
      {isOpen && hasContent && (
        <div className="mt-1 animate-in slide-in-from-top-2 duration-200">
          {/* Subfolders */}
          {folder.subfolders.map((subfolder) => (
            <FolderItem key={subfolder.path} folder={subfolder} level={level + 1} />
          ))}
          
          {/* Notes */}
          {folder.notes.map((note) => {
            const isActive = location.pathname === `/notes/${note.slug}`;
            
            return (
              <Link
                key={note.slug}
                to={note.isHome ? '/' : `/notes/${note.slug}`}
                className={cn(
                  "flex items-center gap-2 px-3 py-2 text-sm rounded-md transition-all duration-200",
                  isActive 
                    ? "bg-accent text-accent-foreground font-semibold" 
                    : "text-muted-foreground hover:text-foreground hover:bg-accent/50"
                )}
                style={{ paddingLeft: `${24 + level * 12}px` }}
              >
                {note.isHome ? (
                  <Home className={cn(
                    "w-4 h-4 flex-shrink-0 transition-all duration-200",
                    isActive && "text-primary"
                  )} />
                ) : (
                  <FileText className={cn(
                    "w-4 h-4 flex-shrink-0 transition-all duration-200",
                    isActive && "text-primary"
                  )} />
                )}
                <span className="truncate">{note.title}</span>
              </Link>
            );
          })}
        </div>
      )}
    </div>
  );
}

export function Sidebar() {
  const [isOpen, setIsOpen] = useState(false);
  const location = useLocation();
  const folders = getFolderStructure();
  const homeNote = getHomeNote();
  const { t } = useLocale();
  
  const sidebarContent = (
    <div className="h-full flex flex-col bg-sidebar border-r border-sidebar-border">
      {/* Header with Logo */}
      <div className="p-4 border-b border-sidebar-border space-y-4">
        {/* Brand */}
        <Link 
          to="/" 
          className="flex items-center gap-2 hover:opacity-80 transition-opacity duration-200"
          onClick={() => setIsOpen(false)}
        >
          <div className="w-8 h-8 bg-gradient-to-br from-primary to-primary/60 rounded-lg flex items-center justify-center shadow-sm">
            <Sprout className="w-5 h-5 text-primary-foreground" />
          </div>
          <div className="min-w-0">
            <h2 className="text-sm font-semibold text-sidebar-foreground truncate">
              {t.sidebar.digitalGarden}
            </h2>
            <p className="text-xs text-sidebar-muted-foreground truncate">
              {t.sidebar?.home || 'Knowledge Base'}
            </p>
          </div>
        </Link>

        {/* Controls */}
        <div className="flex items-center gap-2">
          <ThemeToggle />
          <LanguageSwitcher />
        </div>
        
        {/* Search */}
        <SearchBar onNavigate={() => setIsOpen(false)} />
      </div>
      
      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto py-4 space-y-1">
        {/* Section: Main */}
        {homeNote && (
          <div className="px-2 space-y-1">
            <Link
              to="/"
              className={cn(
                "flex items-center gap-2 px-4 py-2 text-sm rounded-md transition-all duration-200",
                location.pathname === '/'
                  ? "bg-accent text-accent-foreground font-semibold"
                  : "text-muted-foreground hover:text-foreground hover:bg-accent/50"
              )}
              onClick={() => setIsOpen(false)}
            >
              <Home className={cn(
                "w-4 h-4 transition-all duration-200",
                location.pathname === '/' && "text-primary w-5 h-5"
              )} />
              <span>{t.sidebar.home}</span>
            </Link>
          </div>
        )}

        {/* Section: Explore */}
        <div className="px-2 space-y-1">
          <div className="px-2 py-1 text-xs font-semibold text-muted-foreground uppercase tracking-wider">
            {t.sidebar?.explore || 'Explore'}
          </div>
          <Link
            to="/graph"
            className={cn(
              "flex items-center gap-2 px-4 py-2 text-sm rounded-md transition-all duration-200",
              location.pathname === '/graph'
                ? "bg-accent text-accent-foreground font-semibold"
                : "text-muted-foreground hover:text-foreground hover:bg-accent/50"
            )}
            onClick={() => setIsOpen(false)}
          >
            <Network className={cn(
              "w-4 h-4 transition-all duration-200",
              location.pathname === '/graph' && "text-primary w-5 h-5"
            )} />
            <span>{t.sidebar.graph}</span>
          </Link>

          <Link
            to="/chat"
            className={cn(
              "flex items-center gap-2 px-4 py-2 text-sm rounded-md transition-all duration-200",
              location.pathname === '/chat'
                ? "bg-accent text-accent-foreground font-semibold"
                : "text-muted-foreground hover:text-foreground hover:bg-accent/50"
            )}
            onClick={() => setIsOpen(false)}
          >
            <MessageSquare className={cn(
              "w-4 h-4 transition-all duration-200",
              location.pathname === '/chat' && "text-primary w-5 h-5"
            )} />
            <span>{t.sidebar.chat}</span>
          </Link>
        </div>
        
        {/* Section: Content */}
        {folders.length > 0 && (
          <div className="px-2 space-y-1 mt-4">
            <div className="px-2 py-1 text-xs font-semibold text-muted-foreground uppercase tracking-wider">
              {t.sidebar?.content || 'Content'}
            </div>
            <div className="mt-2">
              {folders.map((folder) => (
                <FolderItem key={folder.path} folder={folder} />
              ))}
            </div>
          </div>
        )}
      </nav>
    </div>
  );
  
  return (
    <>
      {/* Mobile toggle */}
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="fixed top-4 left-4 z-40 p-2 bg-background border border-border rounded-md shadow-sm lg:hidden hover:bg-accent transition-colors duration-200"
        aria-label={t.sidebar.toggleNavigation}
      >
        {isOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
      </button>
      
      {/* Mobile overlay */}
      {isOpen && (
        <div 
          className="fixed inset-0 bg-black/50 z-30 lg:hidden animate-in fade-in duration-200"
          onClick={() => setIsOpen(false)}
        />
      )}
      
      {/* Mobile sidebar */}
      <aside
        className={cn(
          "fixed top-0 left-0 z-30 w-64 h-full transform transition-transform duration-200 lg:hidden",
          isOpen ? "translate-x-0" : "-translate-x-full"
        )}
      >
        {sidebarContent}
      </aside>
      
      {/* Desktop sidebar */}
      <aside className="hidden lg:block w-64 h-screen sticky top-0 flex-shrink-0">
        {sidebarContent}
      </aside>
    </>
  );
}
