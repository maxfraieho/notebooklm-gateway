 import { 
   Bold, 
   Italic, 
   Heading1, 
   Heading2, 
   Heading3,
   Link, 
   Code, 
   List, 
   ListOrdered, 
   Quote, 
   Table,
   Link2,
   Minus,
   Strikethrough,
   Type,
 } from 'lucide-react';
 import { Button } from '@/components/ui/button';
 import {
   Tooltip,
   TooltipContent,
   TooltipTrigger,
 } from '@/components/ui/tooltip';
 import { ScrollArea, ScrollBar } from '@/components/ui/scroll-area';
 import { useLocale } from '@/hooks/useLocale';
 import { cn } from '@/lib/utils';
 
 interface EditorToolbarProps {
   onFormat: (before: string, after?: string) => void;
   onInsertWikilink: () => void;
   disabled?: boolean;
   className?: string;
 }
 
 export function EditorToolbar({ 
   onFormat, 
   onInsertWikilink,
   disabled = false,
   className
 }: EditorToolbarProps) {
   const { t } = useLocale();
 
   const tools = [
     // Headings
     {
       icon: Heading1,
       label: t.editor?.toolbar?.heading1 || 'H1',
       shortcut: 'Ctrl+1',
       action: () => onFormat('# ', ''),
     },
     {
       icon: Heading2,
       label: t.editor?.toolbar?.heading2 || 'H2',
       shortcut: 'Ctrl+2',
       action: () => onFormat('## ', ''),
     },
     {
       icon: Heading3,
       label: t.editor?.toolbar?.heading3 || 'H3',
       shortcut: 'Ctrl+3',
       action: () => onFormat('### ', ''),
     },
     { type: 'separator' as const },
     // Text formatting
     {
       icon: Bold,
       label: t.editor?.toolbar?.bold || 'Bold',
       shortcut: 'Ctrl+B',
       action: () => onFormat('**', '**'),
     },
     {
       icon: Italic,
       label: t.editor?.toolbar?.italic || 'Italic',
       shortcut: 'Ctrl+I',
       action: () => onFormat('*', '*'),
     },
     {
       icon: Strikethrough,
       label: t.editor?.toolbar?.strikethrough || 'Strikethrough',
       action: () => onFormat('~~', '~~'),
     },
     {
       icon: Code,
       label: t.editor?.toolbar?.code || 'Code',
       action: () => onFormat('`', '`'),
     },
     { type: 'separator' as const },
     // Lists
     {
       icon: List,
       label: t.editor?.toolbar?.bulletList || 'Bullet list',
       action: () => onFormat('- ', ''),
     },
     {
       icon: ListOrdered,
       label: t.editor?.toolbar?.numberedList || 'Numbered list',
       action: () => onFormat('1. ', ''),
     },
     {
       icon: Quote,
       label: t.editor?.toolbar?.quote || 'Quote',
       action: () => onFormat('> ', ''),
     },
     { type: 'separator' as const },
     // Links
     {
       icon: Link,
       label: t.editor?.toolbar?.link || 'Link',
       shortcut: 'Ctrl+K',
       action: () => onFormat('[', '](url)'),
     },
     {
       icon: Link2,
       label: t.editor?.toolbar?.wikilink || 'Wikilink',
       action: onInsertWikilink,
     },
     { type: 'separator' as const },
     // Blocks
     {
       icon: Minus,
       label: t.editor?.toolbar?.hr || 'Divider',
       action: () => onFormat('\n---\n', ''),
     },
     {
       icon: Table,
       label: t.editor?.toolbar?.table || 'Table',
       action: () => onFormat(
         '\n| Column 1 | Column 2 | Column 3 |\n|----------|----------|----------|\n| Cell     | Cell     | Cell     |\n',
         ''
       ),
     },
     {
       icon: Type,
       label: t.editor?.toolbar?.codeBlock || 'Code block',
       action: () => onFormat('\n```\n', '\n```\n'),
     },
   ];
 
   return (
     <div className={cn("border-b border-border bg-muted/30", className)}>
       <ScrollArea className="w-full">
         <div className="flex items-center gap-0.5 p-1.5 min-w-max">
           {tools.map((tool, index) => {
             if ('type' in tool && tool.type === 'separator') {
               return (
                 <div 
                   key={`sep-${index}`} 
                   className="w-px h-6 bg-border mx-1.5" 
                 />
               );
             }
 
             const ToolIcon = tool.icon;
             
             return (
               <Tooltip key={tool.label} delayDuration={300}>
                 <TooltipTrigger asChild>
                   <Button
                     type="button"
                     variant="ghost"
                     size="icon"
                     className={cn(
                       "h-7 w-7 rounded-sm",
                       "hover:bg-primary/10 hover:text-primary",
                       "focus-visible:ring-1 focus-visible:ring-primary"
                     )}
                     onClick={tool.action}
                     disabled={disabled}
                   >
                     <ToolIcon className="h-4 w-4" />
                     <span className="sr-only">{tool.label}</span>
                   </Button>
                 </TooltipTrigger>
                 <TooltipContent side="bottom" className="text-xs flex items-center gap-2">
                   <span>{tool.label}</span>
                   {'shortcut' in tool && tool.shortcut && (
                     <kbd className="px-1.5 py-0.5 text-[10px] font-mono bg-muted rounded">
                       {tool.shortcut}
                     </kbd>
                   )}
                 </TooltipContent>
               </Tooltip>
             );
           })}
         </div>
         <ScrollBar orientation="horizontal" className="h-1.5" />
       </ScrollArea>
     </div>
   );
 }