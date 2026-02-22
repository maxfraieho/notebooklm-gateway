 import { useEffect, useRef } from 'react';
 import { useWikilinkSuggestions, type WikilinkSuggestion } from '@/hooks/useWikilinkSuggestions';
 import { FileText } from 'lucide-react';
 import { cn } from '@/lib/utils';
 
 interface WikilinkAutocompleteProps {
   query: string;
   isOpen: boolean;
   onSelect: (suggestion: WikilinkSuggestion) => void;
   onClose: () => void;
   position?: { top: number; left: number };
 }
 
 export function WikilinkAutocomplete({
   query,
   isOpen,
   onSelect,
   onClose,
   position,
 }: WikilinkAutocompleteProps) {
   const suggestions = useWikilinkSuggestions(query);
   const containerRef = useRef<HTMLDivElement>(null);
   const selectedIndex = useRef(0);
 
   // Reset selection when suggestions change
   useEffect(() => {
     selectedIndex.current = 0;
   }, [suggestions]);
 
   // Handle keyboard navigation
   useEffect(() => {
     if (!isOpen) return;
 
     const handleKeyDown = (e: KeyboardEvent) => {
       if (e.key === 'Escape') {
         e.preventDefault();
         onClose();
         return;
       }
 
       if (e.key === 'ArrowDown') {
         e.preventDefault();
         selectedIndex.current = Math.min(
           selectedIndex.current + 1,
           suggestions.length - 1
         );
         containerRef.current?.querySelector(`[data-index="${selectedIndex.current}"]`)
           ?.scrollIntoView({ block: 'nearest' });
       }
 
       if (e.key === 'ArrowUp') {
         e.preventDefault();
         selectedIndex.current = Math.max(selectedIndex.current - 1, 0);
         containerRef.current?.querySelector(`[data-index="${selectedIndex.current}"]`)
           ?.scrollIntoView({ block: 'nearest' });
       }
 
       if (e.key === 'Enter' || e.key === 'Tab') {
         if (suggestions.length > 0) {
           e.preventDefault();
           onSelect(suggestions[selectedIndex.current]);
         }
       }
     };
 
     document.addEventListener('keydown', handleKeyDown);
     return () => document.removeEventListener('keydown', handleKeyDown);
   }, [isOpen, suggestions, onSelect, onClose]);
 
   if (!isOpen || suggestions.length === 0) {
     return null;
   }
 
   return (
     <div
       ref={containerRef}
       className="absolute z-50 w-64 max-h-48 overflow-y-auto bg-popover border border-border rounded-md shadow-lg"
       style={position ? { top: position.top, left: position.left } : undefined}
     >
       <div className="py-1">
         {suggestions.map((suggestion, index) => (
           <button
             key={suggestion.slug}
             data-index={index}
             type="button"
             className={cn(
               "w-full px-3 py-2 text-left text-sm flex items-center gap-2 hover:bg-accent transition-colors",
               index === selectedIndex.current && "bg-accent"
             )}
             onClick={() => onSelect(suggestion)}
           >
             <FileText className="h-4 w-4 text-muted-foreground shrink-0" />
             <span className="truncate">{suggestion.title}</span>
           </button>
         ))}
       </div>
     </div>
   );
 }