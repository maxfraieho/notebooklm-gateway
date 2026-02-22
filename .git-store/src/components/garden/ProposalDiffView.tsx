 // Proposal Diff View Component
 // Shows side-by-side or unified diff of original vs proposed content
 
 import { useMemo } from 'react';
 import { cn } from '@/lib/utils';
 import { Badge } from '@/components/ui/badge';
 import { ScrollArea } from '@/components/ui/scroll-area';
 import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
 import { Columns, AlignJustify } from 'lucide-react';
 
 interface ProposalDiffViewProps {
   originalContent: string;
   proposedContent: string;
   className?: string;
 }
 
 // Simple diff algorithm - find changed lines
 function computeDiff(original: string, proposed: string) {
   const originalLines = original.split('\n');
   const proposedLines = proposed.split('\n');
   
   const maxLen = Math.max(originalLines.length, proposedLines.length);
   const diff: Array<{
     type: 'unchanged' | 'removed' | 'added' | 'modified';
     originalLine?: string;
     proposedLine?: string;
     lineNum: number;
   }> = [];
   
   for (let i = 0; i < maxLen; i++) {
     const origLine = originalLines[i];
     const propLine = proposedLines[i];
     
     if (origLine === propLine) {
       diff.push({
         type: 'unchanged',
         originalLine: origLine,
         proposedLine: propLine,
         lineNum: i + 1,
       });
     } else if (origLine === undefined) {
       diff.push({
         type: 'added',
         proposedLine: propLine,
         lineNum: i + 1,
       });
     } else if (propLine === undefined) {
       diff.push({
         type: 'removed',
         originalLine: origLine,
         lineNum: i + 1,
       });
     } else {
       diff.push({
         type: 'modified',
         originalLine: origLine,
         proposedLine: propLine,
         lineNum: i + 1,
       });
     }
   }
   
   return diff;
 }
 
 export function ProposalDiffView({ originalContent, proposedContent, className }: ProposalDiffViewProps) {
   const diff = useMemo(() => computeDiff(originalContent, proposedContent), [originalContent, proposedContent]);
   
   const stats = useMemo(() => {
     let added = 0, removed = 0, modified = 0;
     diff.forEach(d => {
       if (d.type === 'added') added++;
       if (d.type === 'removed') removed++;
       if (d.type === 'modified') modified++;
     });
     return { added, removed, modified };
   }, [diff]);
 
   return (
     <div className={cn("space-y-4", className)}>
       {/* Stats */}
       <div className="flex items-center gap-2 flex-wrap">
         {stats.added > 0 && (
           <Badge variant="outline" className="text-green-600 border-green-600/30 bg-green-50 dark:bg-green-900/20">
             +{stats.added} added
           </Badge>
         )}
         {stats.removed > 0 && (
           <Badge variant="outline" className="text-red-600 border-red-600/30 bg-red-50 dark:bg-red-900/20">
             -{stats.removed} removed
           </Badge>
         )}
         {stats.modified > 0 && (
           <Badge variant="outline" className="text-yellow-600 border-yellow-600/30 bg-yellow-50 dark:bg-yellow-900/20">
             ~{stats.modified} modified
           </Badge>
         )}
       </div>
 
       <Tabs defaultValue="side" className="w-full">
         <TabsList>
           <TabsTrigger value="side">
             <Columns className="h-4 w-4 mr-2" />
             Side by Side
           </TabsTrigger>
           <TabsTrigger value="unified">
             <AlignJustify className="h-4 w-4 mr-2" />
             Unified
           </TabsTrigger>
         </TabsList>
         
         <TabsContent value="side" className="mt-4">
           <div className="grid grid-cols-2 gap-2 rounded-lg border overflow-hidden">
             {/* Original */}
             <div className="border-r">
               <div className="bg-muted px-3 py-2 text-sm font-medium border-b">
                 Original
               </div>
               <ScrollArea className="h-[400px]">
                 <div className="font-mono text-xs p-2">
                   {diff.map((d, i) => (
                     <div
                       key={i}
                       className={cn(
                         "px-2 py-0.5",
                         d.type === 'removed' && "bg-red-100 dark:bg-red-900/30 text-red-800 dark:text-red-200",
                         d.type === 'modified' && "bg-yellow-100 dark:bg-yellow-900/30 text-yellow-800 dark:text-yellow-200"
                       )}
                     >
                       <span className="text-muted-foreground w-8 inline-block">{d.lineNum}</span>
                       {d.originalLine ?? ''}
                     </div>
                   ))}
                 </div>
               </ScrollArea>
             </div>
             
             {/* Proposed */}
             <div>
               <div className="bg-muted px-3 py-2 text-sm font-medium border-b">
                 Proposed
               </div>
               <ScrollArea className="h-[400px]">
                 <div className="font-mono text-xs p-2">
                   {diff.map((d, i) => (
                     <div
                       key={i}
                       className={cn(
                         "px-2 py-0.5",
                         d.type === 'added' && "bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-200",
                         d.type === 'modified' && "bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-200"
                       )}
                     >
                       <span className="text-muted-foreground w-8 inline-block">{d.lineNum}</span>
                       {d.proposedLine ?? ''}
                     </div>
                   ))}
                 </div>
               </ScrollArea>
             </div>
           </div>
         </TabsContent>
         
         <TabsContent value="unified" className="mt-4">
           <ScrollArea className="h-[400px] rounded-lg border">
             <div className="font-mono text-xs p-2">
               {diff.map((d, i) => {
                 if (d.type === 'unchanged') {
                   return (
                     <div key={i} className="px-2 py-0.5">
                       <span className="text-muted-foreground w-8 inline-block">{d.lineNum}</span>
                       <span className="w-4 inline-block text-muted-foreground">&nbsp;</span>
                       {d.originalLine}
                     </div>
                   );
                 }
                 if (d.type === 'removed') {
                   return (
                     <div key={i} className="px-2 py-0.5 bg-red-100 dark:bg-red-900/30 text-red-800 dark:text-red-200">
                       <span className="w-8 inline-block">{d.lineNum}</span>
                       <span className="w-4 inline-block font-bold">-</span>
                       {d.originalLine}
                     </div>
                   );
                 }
                 if (d.type === 'added') {
                   return (
                     <div key={i} className="px-2 py-0.5 bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-200">
                       <span className="w-8 inline-block">{d.lineNum}</span>
                       <span className="w-4 inline-block font-bold">+</span>
                       {d.proposedLine}
                     </div>
                   );
                 }
                 // Modified - show both lines
                 return (
                   <div key={i}>
                     <div className="px-2 py-0.5 bg-red-100 dark:bg-red-900/30 text-red-800 dark:text-red-200">
                       <span className="w-8 inline-block">{d.lineNum}</span>
                       <span className="w-4 inline-block font-bold">-</span>
                       {d.originalLine}
                     </div>
                     <div className="px-2 py-0.5 bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-200">
                       <span className="w-8 inline-block">&nbsp;</span>
                       <span className="w-4 inline-block font-bold">+</span>
                       {d.proposedLine}
                     </div>
                   </div>
                 );
               })}
             </div>
           </ScrollArea>
         </TabsContent>
       </Tabs>
     </div>
   );
 }