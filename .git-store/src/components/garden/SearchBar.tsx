// Search bar component for Digital Garden
import { useState, useRef, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Search, X, FileText } from 'lucide-react';
import { useSearch } from '@/hooks/useSearch';
import { useLocale, interpolate } from '@/hooks/useLocale';
import { cn } from '@/lib/utils';

interface SearchBarProps {
  className?: string;
  onNavigate?: () => void;
}

export function SearchBar({ className, onNavigate }: SearchBarProps) {
  const { query, setQuery, results, clearSearch, isSearching } = useSearch();
  const [isOpen, setIsOpen] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const navigate = useNavigate();
  const { t } = useLocale();
  
  // Close dropdown when clicking outside
  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (containerRef.current && !containerRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    }
    
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);
  
  // Handle keyboard navigation
  useEffect(() => {
    function handleKeyDown(event: KeyboardEvent) {
      // Open search with Cmd/Ctrl + K
      if ((event.metaKey || event.ctrlKey) && event.key === 'k') {
        event.preventDefault();
        inputRef.current?.focus();
        setIsOpen(true);
      }
      
      // Close with Escape
      if (event.key === 'Escape' && isOpen) {
        setIsOpen(false);
        inputRef.current?.blur();
      }
    }
    
    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [isOpen]);
  
  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setQuery(e.target.value);
    if (e.target.value.trim()) {
      setIsOpen(true);
    }
  };
  
  const handleClear = () => {
    clearSearch();
    setIsOpen(false);
  };
  
  const handleResultClick = (slug: string) => {
    const currentQuery = query; // Capture before clearing
    setIsOpen(false);
    clearSearch();
    onNavigate?.();
    // Navigate with search query in state for highlighting
    navigate(`/notes/${slug}`, { state: { searchQuery: currentQuery } });
  };
  
  return (
    <div ref={containerRef} className={cn("relative", className)}>
      {/* Search Input */}
      <div className="relative">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground pointer-events-none" />
        <input
          ref={inputRef}
          type="text"
          value={query}
          onChange={handleInputChange}
          onFocus={() => isSearching && setIsOpen(true)}
          placeholder={t.search.placeholder}
          className={cn(
            "w-full pl-10 pr-10 py-2 text-sm",
            "bg-background border border-border rounded-md",
            "placeholder:text-muted-foreground",
            "focus:outline-none focus:ring-2 focus:ring-ring focus:border-transparent",
            "transition-colors"
          )}
        />
        {isSearching && (
          <button
            onClick={handleClear}
            className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground transition-colors"
            aria-label={t.search.clearSearch}
          >
            <X className="w-4 h-4" />
          </button>
        )}
        {!isSearching && (
          <kbd className="absolute right-3 top-1/2 -translate-y-1/2 hidden sm:inline-flex h-5 select-none items-center gap-1 rounded border bg-muted px-1.5 font-mono text-[10px] font-medium text-muted-foreground">
            <span className="text-xs">⌘</span>K
          </kbd>
        )}
      </div>
      
      {/* Results Dropdown */}
      {isOpen && isSearching && (
        <div className="absolute top-full left-0 right-0 mt-2 bg-popover border border-border rounded-md shadow-lg z-50 max-h-80 overflow-y-auto">
          {results.length > 0 ? (
            <ul className="py-2">
              {results.map((result) => (
                <li key={result.slug}>
                  <button
                    onClick={() => handleResultClick(result.slug)}
                    className="w-full text-left flex items-start gap-3 px-4 py-3 hover:bg-accent transition-colors"
                  >
                    <FileText className="w-4 h-4 mt-0.5 text-muted-foreground flex-shrink-0" />
                    <div className="min-w-0 flex-1">
                      <div className="font-medium text-foreground truncate">
                        {result.title}
                      </div>
                      <p className="text-sm text-muted-foreground line-clamp-2 mt-0.5">
                        {result.excerpt}
                      </p>
                    </div>
                  </button>
                </li>
              ))}
            </ul>
          ) : (
            <div className="px-4 py-8 text-center text-muted-foreground">
              <p className="text-sm">{interpolate(t.search.noResults, { query })}</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
