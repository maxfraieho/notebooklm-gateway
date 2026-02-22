import { Link, useLocation } from 'react-router-dom';
import { Sprout, Network, MessageSquare, Edit3, FolderTree, Home, GitBranch } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { SearchBar } from './SearchBar';
import { ThemeToggle } from './ThemeToggle';
import { LanguageSwitcher } from './LanguageSwitcher';
import { OwnerMenu } from './OwnerMenu';
import { useLocale } from '@/hooks/useLocale';
import { useOwnerAuth } from '@/hooks/useOwnerAuth';
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from '@/components/ui/tooltip';

export function GardenHeader() {
  const { t } = useLocale();
  const { isAuthenticated } = useOwnerAuth();
  const location = useLocation();

  // Determine next navigation in cycle
  const getCycleNavigation = () => {
    const isEditorPage = location.pathname === '/notes/new' || location.pathname.endsWith('/edit');
    const isDrakonPage = location.pathname === '/drakon';
    
    if (location.pathname === '/' || location.pathname === '') {
      return { to: '/files', icon: FolderTree, tooltip: t.sidebar?.fileStructure || 'File Structure' };
    }
    if (location.pathname === '/files') {
      return { to: '/chat', icon: MessageSquare, tooltip: t.sidebar?.chat || 'Chat' };
    }
    if (location.pathname === '/chat') {
      return { to: '/graph', icon: Network, tooltip: t.index?.viewGraph || 'Graph' };
    }
    if (location.pathname === '/graph') {
      return { to: '/notes/new', icon: Edit3, tooltip: t.editor?.newNote || 'New Note' };
    }
    if (isEditorPage) {
      return { to: '/drakon', icon: GitBranch, tooltip: 'DRAKON Editor' };
    }
    if (isDrakonPage) {
      return { to: '/', icon: Home, tooltip: t.sidebar?.home || 'Home' };
    }
    // Default for other pages (notes, tags, etc)
    return { to: '/', icon: Home, tooltip: t.sidebar?.home || 'Home' };
  };

  const cycle = getCycleNavigation();
  const CycleIcon = cycle.icon;

  return (
    <header className="sticky top-0 z-[60] bg-card/95 backdrop-blur-sm border-b border-border shadow-sm transition-all duration-200">
      <div className="max-w-7xl mx-auto px-4 h-16 flex items-center justify-between gap-4">
        {/* Left: Cycle Button */}
        <Tooltip>
          <TooltipTrigger asChild>
            <Button 
              asChild 
              variant="ghost" 
              size="icon" 
              className="shrink-0 hover:bg-accent/50 transition-colors duration-200"
            >
              <Link to={cycle.to} aria-label={cycle.tooltip}>
                <CycleIcon className="w-5 h-5" />
              </Link>
            </Button>
          </TooltipTrigger>
          <TooltipContent>{cycle.tooltip}</TooltipContent>
        </Tooltip>

        {/* Logo & Brand */}
        <Link
          to="/"
          className="flex items-center gap-3 flex-shrink-0 group hover:opacity-80 transition-opacity duration-200"
        >
          <div className="w-8 h-8 bg-gradient-to-br from-primary to-primary/60 rounded-lg flex items-center justify-center shadow-sm group-hover:shadow-md transition-shadow duration-200">
            <Sprout className="w-5 h-5 text-primary-foreground" />
          </div>
          <div className="hidden sm:block">
            <h1 className="text-lg font-semibold text-foreground leading-tight">
              Digital Garden
            </h1>
            <p className="text-xs text-muted-foreground">Knowledge Base</p>
          </div>
        </Link>

        {/* Center: Search Bar (expanded) */}
        <div className="flex-1 max-w-2xl">
          <SearchBar />
        </div>

        {/* Right: Quick Navigation + Actions */}
        <div className="flex items-center gap-1 flex-shrink-0">
          {/* Quick Navigation Icons */}
          <div className="hidden sm:flex items-center gap-1">
            {/* Chat */}
            <Tooltip>
              <TooltipTrigger asChild>
                <Button 
                  asChild 
                  variant={location.pathname === '/chat' ? 'default' : 'ghost'} 
                  size="icon"
                  className="h-8 w-8"
                >
                  <Link to="/chat" aria-label={t.sidebar?.chat || 'Chat'}>
                    <MessageSquare className="w-4 h-4" />
                  </Link>
                </Button>
              </TooltipTrigger>
              <TooltipContent>{t.sidebar?.chat || 'Chat'}</TooltipContent>
            </Tooltip>

            {/* Graph */}
            <Tooltip>
              <TooltipTrigger asChild>
                <Button 
                  asChild 
                  variant={location.pathname === '/graph' ? 'default' : 'ghost'} 
                  size="icon"
                  className="h-8 w-8"
                >
                  <Link to="/graph" aria-label={t.index?.viewGraph || 'Graph'}>
                    <Network className="w-4 h-4" />
                  </Link>
                </Button>
              </TooltipTrigger>
              <TooltipContent>{t.index?.viewGraph || 'Graph'}</TooltipContent>
            </Tooltip>

            {/* New Note - only show for authenticated users */}
            {isAuthenticated && (
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button 
                    asChild 
                    variant="ghost" 
                    size="icon"
                    className="h-8 w-8"
                  >
                    <Link to="/notes/new" aria-label={t.editor?.newNote || 'New Note'}>
                      <Edit3 className="w-4 h-4" />
                    </Link>
                  </Button>
                </TooltipTrigger>
                <TooltipContent>{t.editor?.newNote || 'New Note'}</TooltipContent>
              </Tooltip>
            )}

            {/* DRAKON Editor - only show for authenticated users */}
            {isAuthenticated && (
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button 
                    asChild 
                    variant={location.pathname === '/drakon' ? 'default' : 'ghost'} 
                    size="icon"
                    className="h-8 w-8"
                  >
                    <Link to="/drakon" aria-label="DRAKON Editor">
                      <GitBranch className="w-4 h-4" />
                    </Link>
                  </Button>
                </TooltipTrigger>
                <TooltipContent>DRAKON Editor</TooltipContent>
              </Tooltip>
            )}
          </div>

          {/* Divider */}
          <div className="hidden sm:block w-px h-6 bg-border mx-1" />

          {/* Theme Toggle */}
          <Tooltip>
            <TooltipTrigger asChild>
              <ThemeToggle />
            </TooltipTrigger>
            <TooltipContent>
              {t.common?.toggleTheme || 'Toggle theme'}
            </TooltipContent>
          </Tooltip>

          {/* Language Switcher */}
          <Tooltip>
            <TooltipTrigger asChild>
              <div className="inline-flex">
                <LanguageSwitcher />
              </div>
            </TooltipTrigger>
            <TooltipContent>
              {t.common?.language || 'Language'}
            </TooltipContent>
          </Tooltip>

          {/* Owner Menu - Only for authenticated users */}
          {isAuthenticated && <OwnerMenu />}
        </div>
      </div>
    </header>
  );
}
