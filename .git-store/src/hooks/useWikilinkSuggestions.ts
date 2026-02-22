 import { useMemo } from 'react';
 import { getAllNotes } from '@/lib/notes/noteLoader';
 
 export interface WikilinkSuggestion {
   title: string;
   slug: string;
 }
 
 export function useWikilinkSuggestions(query: string): WikilinkSuggestion[] {
   const allNotes = useMemo(() => getAllNotes(), []);
 
   const suggestions = useMemo(() => {
     if (!query || query.length < 1) return [];
     
     const q = query.toLowerCase().trim();
     
     return allNotes
       .filter(note => {
         const titleMatch = note.title.toLowerCase().includes(q);
         const slugMatch = decodeURIComponent(note.slug).toLowerCase().includes(q);
         return titleMatch || slugMatch;
       })
       .slice(0, 10)
       .map(note => ({
         title: note.title,
         slug: note.slug,
       }));
   }, [query, allNotes]);
 
   return suggestions;
 }
 
 // Hook to detect wikilink input pattern
 export function useWikilinkDetection(
   content: string,
   cursorPosition: number
 ): { isActive: boolean; query: string; startIndex: number } {
   return useMemo(() => {
     // Look backwards from cursor for [[
     const beforeCursor = content.substring(0, cursorPosition);
     const lastOpenBracket = beforeCursor.lastIndexOf('[[');
     
     if (lastOpenBracket === -1) {
       return { isActive: false, query: '', startIndex: -1 };
     }
     
     // Check if there's a closing ]] between [[ and cursor
     const betweenBrackets = beforeCursor.substring(lastOpenBracket + 2);
     if (betweenBrackets.includes(']]')) {
       return { isActive: false, query: '', startIndex: -1 };
     }
     
     // Extract the query (text after [[)
     const query = betweenBrackets;
     
     // Don't activate if query contains newlines
     if (query.includes('\n')) {
       return { isActive: false, query: '', startIndex: -1 };
     }
     
     return {
       isActive: true,
       query,
       startIndex: lastOpenBracket,
     };
   }, [content, cursorPosition]);
 }