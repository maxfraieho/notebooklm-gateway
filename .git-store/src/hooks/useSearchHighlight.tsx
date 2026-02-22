// Hook and context for search highlight functionality
import { createContext, useContext, useState, useEffect, useCallback, useRef } from 'react';
import { useLocation } from 'react-router-dom';

interface SearchHighlightState {
  query: string | null;
  isActive: boolean;
  clearHighlight: () => void;
}

const SearchHighlightContext = createContext<SearchHighlightState>({
  query: null,
  isActive: false,
  clearHighlight: () => {},
});

export function useSearchHighlight() {
  return useContext(SearchHighlightContext);
}

interface SearchHighlightProviderProps {
  children: React.ReactNode;
}

export function SearchHighlightProvider({ children }: SearchHighlightProviderProps) {
  const location = useLocation();
  const [query, setQuery] = useState<string | null>(null);
  const [isActive, setIsActive] = useState(false);
  const hasScrolledRef = useRef(false);
  const initialScrollDoneRef = useRef(false);
  
  // Extract query from router state
  useEffect(() => {
    const state = location.state as { searchQuery?: string } | null;
    if (state?.searchQuery) {
      setQuery(state.searchQuery);
      setIsActive(true);
      hasScrolledRef.current = false;
      initialScrollDoneRef.current = false;
    } else {
      setQuery(null);
      setIsActive(false);
    }
  }, [location]);
  
  // Clear highlight on user scroll
  useEffect(() => {
    if (!isActive) return;
    
    let scrollTimeout: number;
    
    function handleScroll() {
      // Ignore the initial programmatic scroll
      if (!initialScrollDoneRef.current) {
        initialScrollDoneRef.current = true;
        return;
      }
      
      // Debounce scroll detection
      clearTimeout(scrollTimeout);
      scrollTimeout = window.setTimeout(() => {
        if (!hasScrolledRef.current) {
          hasScrolledRef.current = true;
          setIsActive(false);
        }
      }, 50);
    }
    
    // Small delay to allow initial programmatic scroll
    const setupTimeout = window.setTimeout(() => {
      window.addEventListener('scroll', handleScroll, { passive: true });
    }, 500);
    
    return () => {
      clearTimeout(setupTimeout);
      clearTimeout(scrollTimeout);
      window.removeEventListener('scroll', handleScroll);
    };
  }, [isActive]);
  
  const clearHighlight = useCallback(() => {
    setIsActive(false);
  }, []);
  
  return (
    <SearchHighlightContext.Provider value={{ query, isActive, clearHighlight }}>
      {children}
    </SearchHighlightContext.Provider>
  );
}

/**
 * Hook to scroll to first match and return highlight info
 */
export function useScrollToMatch(contentRef: React.RefObject<HTMLElement>) {
  const { query, isActive } = useSearchHighlight();
  const hasScrolledToMatchRef = useRef(false);
  
  useEffect(() => {
    if (!query || !isActive || !contentRef.current || hasScrolledToMatchRef.current) {
      return;
    }
    
    // Find the first text node containing the query
    const walker = document.createTreeWalker(
      contentRef.current,
      NodeFilter.SHOW_TEXT,
      {
        acceptNode: (node) => {
          const text = node.textContent?.toLowerCase() || '';
          return text.includes(query.toLowerCase())
            ? NodeFilter.FILTER_ACCEPT
            : NodeFilter.FILTER_SKIP;
        },
      }
    );
    
    const firstMatch = walker.nextNode();
    
    if (firstMatch && firstMatch.parentElement) {
      hasScrolledToMatchRef.current = true;
      
      // Scroll the parent element into view
      const element = firstMatch.parentElement;
      
      // Small delay to ensure render is complete
      requestAnimationFrame(() => {
        element.scrollIntoView({ behavior: 'smooth', block: 'center' });
      });
    }
  }, [query, isActive, contentRef]);
  
  // Reset on query change
  useEffect(() => {
    hasScrolledToMatchRef.current = false;
  }, [query]);
  
  return { query: isActive ? query : null };
}
