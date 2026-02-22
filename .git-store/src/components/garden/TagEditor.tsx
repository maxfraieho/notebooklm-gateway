 import { useState, useCallback, useRef, KeyboardEvent } from 'react';
 import { X, Plus } from 'lucide-react';
 import { Badge } from '@/components/ui/badge';
 import { Input } from '@/components/ui/input';
 import { Button } from '@/components/ui/button';
 import { useAllTags } from '@/hooks/useTags';
 import { cn } from '@/lib/utils';
 
 interface TagEditorProps {
   tags: string[];
   onChange: (tags: string[]) => void;
   placeholder?: string;
   disabled?: boolean;
 }
 
 export function TagEditor({ 
   tags, 
   onChange, 
   placeholder = 'Add tag...',
   disabled = false 
 }: TagEditorProps) {
   const [inputValue, setInputValue] = useState('');
   const [showSuggestions, setShowSuggestions] = useState(false);
   const inputRef = useRef<HTMLInputElement>(null);
  const allTagInfos = useAllTags();
 
   // Filter suggestions based on input
   const suggestions = inputValue.length > 0
    ? allTagInfos
         .filter(tag => 
          tag.tag.toLowerCase().includes(inputValue.toLowerCase()) &&
          !tags.includes(tag.tag)
         )
         .slice(0, 5)
        .map(t => t.tag)
     : [];
 
   const addTag = useCallback((tag: string) => {
     const trimmed = tag.trim().toLowerCase();
     if (trimmed && !tags.includes(trimmed)) {
       onChange([...tags, trimmed]);
     }
     setInputValue('');
     setShowSuggestions(false);
     inputRef.current?.focus();
   }, [tags, onChange]);
 
   const removeTag = useCallback((tagToRemove: string) => {
     onChange(tags.filter(t => t !== tagToRemove));
   }, [tags, onChange]);
 
   const handleKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
     if (e.key === 'Enter' || e.key === ',') {
       e.preventDefault();
       if (inputValue.trim()) {
         addTag(inputValue);
       }
     }
 
     if (e.key === 'Backspace' && !inputValue && tags.length > 0) {
       removeTag(tags[tags.length - 1]);
     }
 
     if (e.key === 'Escape') {
       setShowSuggestions(false);
     }
   };
 
   return (
     <div className="space-y-2">
       {/* Tag list */}
       <div className="flex flex-wrap gap-1.5">
         {tags.map(tag => (
           <Badge 
             key={tag} 
             variant="secondary"
             className="gap-1 pl-2 pr-1 py-0.5"
           >
             #{tag}
             <button
               type="button"
               onClick={() => removeTag(tag)}
               disabled={disabled}
               className="ml-1 hover:bg-muted rounded-full p-0.5 transition-colors"
             >
               <X className="h-3 w-3" />
               <span className="sr-only">Remove {tag}</span>
             </button>
           </Badge>
         ))}
       </div>
 
       {/* Input with suggestions */}
       <div className="relative">
         <div className="flex gap-2">
           <Input
             ref={inputRef}
             type="text"
             value={inputValue}
             onChange={(e) => {
               setInputValue(e.target.value);
               setShowSuggestions(true);
             }}
             onKeyDown={handleKeyDown}
             onFocus={() => setShowSuggestions(true)}
             onBlur={() => {
               // Delay to allow click on suggestions
               setTimeout(() => setShowSuggestions(false), 150);
             }}
             placeholder={placeholder}
             disabled={disabled}
             className="flex-1"
           />
           <Button
             type="button"
             variant="outline"
             size="icon"
             onClick={() => inputValue.trim() && addTag(inputValue)}
             disabled={disabled || !inputValue.trim()}
           >
             <Plus className="h-4 w-4" />
             <span className="sr-only">Add tag</span>
           </Button>
         </div>
 
         {/* Suggestions dropdown */}
         {showSuggestions && suggestions.length > 0 && (
           <div className="absolute top-full left-0 right-0 mt-1 z-10 bg-popover border border-border rounded-md shadow-lg">
             <div className="py-1">
               {suggestions.map(suggestion => (
                 <button
                   key={suggestion}
                   type="button"
                   className="w-full px-3 py-2 text-left text-sm hover:bg-accent transition-colors"
                   onMouseDown={(e) => {
                     e.preventDefault();
                     addTag(suggestion);
                   }}
                 >
                   #{suggestion}
                 </button>
               ))}
             </div>
           </div>
         )}
       </div>
     </div>
   );
 }