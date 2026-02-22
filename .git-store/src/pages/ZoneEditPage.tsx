 // Zone Edit Page
 // Guest page for editing notes within an access zone (creates proposals)
 
 import { useState, useEffect } from 'react';
 import { useParams, useSearchParams, Link, useNavigate } from 'react-router-dom';
 import { useZoneValidation, type ZoneNote } from '@/hooks/useZoneValidation';
 import { useLocale } from '@/hooks/useLocale';
 import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
 import { Button } from '@/components/ui/button';
 import { Badge } from '@/components/ui/badge';
 import { Input } from '@/components/ui/input';
 import { Label } from '@/components/ui/label';
 import { Textarea } from '@/components/ui/textarea';
 import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
 import { 
   Loader2, 
   ArrowLeft,
   Save,
   Eye,
   Edit3,
   Clock,
   Lock,
   Home,
   Send,
 } from 'lucide-react';
 import { cn } from '@/lib/utils';
 import { ZoneNoteRenderer } from '@/components/garden/ZoneNoteRenderer';
import { ThemeToggle } from '@/components/garden/ThemeToggle';
import { LanguageSwitcher } from '@/components/garden/LanguageSwitcher';
 import { createProposal } from '@/lib/api/mcpGatewayClient';
 import { toast } from 'sonner';
 
 export default function ZoneEditPage() {
   const { zoneId, noteSlug } = useParams<{ zoneId: string; noteSlug: string }>();
   const [searchParams] = useSearchParams();
   const accessCode = searchParams.get('code');
   const navigate = useNavigate();
   const { t } = useLocale();
   
   const { 
     isLoading, 
     isValid, 
     isExpired, 
     error, 
     zone,
     getTimeRemaining,
   } = useZoneValidation(zoneId, accessCode);
 
   const [selectedNote, setSelectedNote] = useState<ZoneNote | null>(null);
   const [editedContent, setEditedContent] = useState('');
   const [guestName, setGuestName] = useState('');
   const [guestEmail, setGuestEmail] = useState('');
   const [isSubmitting, setIsSubmitting] = useState(false);
   const [activeTab, setActiveTab] = useState<'edit' | 'preview'>('edit');
  const [noteLoading, setNoteLoading] = useState(true);
 
  // Find note and initialize content
  useEffect(() => {
    if (!noteSlug) {
      setSelectedNote(null);
      setNoteLoading(false);
      return;
    }

    if (!zone) {
      if (!isLoading) setNoteLoading(false);
      return;
    }

    const decodedParam = decodeURIComponent(noteSlug);
    const normalize = (s: string) => {
      try {
        return decodeURIComponent(s);
      } catch {
        return s;
      }
    };

    const note = zone.notes.find((n) => {
      const raw = n.slug;
      const norm = normalize(raw);
      return raw === decodedParam || norm === decodedParam || raw === noteSlug;
    });

    if (note) {
      setSelectedNote(note);
      setEditedContent(note.content);
    } else {
      setSelectedNote(null);
    }
    setNoteLoading(false);
  }, [zone, noteSlug, isLoading]);
 
   const hasChanges = selectedNote && editedContent !== selectedNote.content;
 
   const handleSubmitProposal = async () => {
     if (!zoneId || !accessCode || !selectedNote || !hasChanges) return;
     
     setIsSubmitting(true);
     try {
       await createProposal(zoneId, accessCode, {
         noteSlug: selectedNote.slug,
         noteTitle: selectedNote.title,
         originalContent: selectedNote.content,
         proposedContent: editedContent,
         guestName: guestName.trim() || undefined,
         guestEmail: guestEmail.trim() || undefined,
       });
       
       toast.success(t.zoneEdit?.proposalSubmitted || 'Edit proposal submitted');
       navigate(`/zone/${zoneId}?code=${accessCode}`);
     } catch (err) {
       toast.error(t.zoneEdit?.proposalFailed || 'Failed to submit proposal');
       console.error('[ZoneEdit] Submit error:', err);
     } finally {
       setIsSubmitting(false);
     }
   };
 
   // Loading state
  if (isLoading || noteLoading) {
     return (
       <div className="min-h-screen bg-background flex items-center justify-center">
         <div className="text-center space-y-4">
           <Loader2 className="h-8 w-8 animate-spin text-primary mx-auto" />
           <p className="text-muted-foreground">{t.zoneView.loading}</p>
         </div>
       </div>
     );
   }
 
   // Expired state
   if (isExpired) {
     return (
       <div className="min-h-screen bg-background flex items-center justify-center p-4">
         <Card className="w-full max-w-md text-center">
           <CardHeader>
             <div className="mx-auto mb-4 w-12 h-12 rounded-full bg-destructive/10 flex items-center justify-center">
               <Clock className="h-6 w-6 text-destructive" />
             </div>
             <CardTitle>{t.zoneView.expired}</CardTitle>
           </CardHeader>
           <CardContent>
             <Button asChild variant="outline">
               <Link to="/">
                 <Home className="mr-2 h-4 w-4" />
                 {t.notFound.returnHome}
               </Link>
             </Button>
           </CardContent>
         </Card>
       </div>
     );
   }
 
  // Error state
  if (!isValid || error) {
     return (
       <div className="min-h-screen bg-background flex items-center justify-center p-4">
         <Card className="w-full max-w-md text-center">
           <CardHeader>
             <div className="mx-auto mb-4 w-12 h-12 rounded-full bg-destructive/10 flex items-center justify-center">
               <Lock className="h-6 w-6 text-destructive" />
             </div>
             <CardTitle>{t.zoneView.accessDenied}</CardTitle>
           </CardHeader>
           <CardContent>
             <Button asChild variant="outline">
               <Link to="/">
                 <Home className="mr-2 h-4 w-4" />
                 {t.notFound.returnHome}
               </Link>
             </Button>
           </CardContent>
         </Card>
       </div>
     );
   }

  // Note not found (zone is valid, but slug doesn't match any note)
  if (!noteLoading && !selectedNote) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center p-4">
        <Card className="w-full max-w-md text-center">
          <CardHeader>
            <div className="mx-auto mb-4 w-12 h-12 rounded-full bg-destructive/10 flex items-center justify-center">
              <Lock className="h-6 w-6 text-destructive" />
            </div>
            <CardTitle>{t.zoneView.invalidZone}</CardTitle>
          </CardHeader>
          <CardContent>
            <Button asChild variant="outline">
              <Link to={`/zone/${zoneId}?code=${encodeURIComponent(accessCode || '')}`}>
                <ArrowLeft className="mr-2 h-4 w-4" />
                {t.zoneView.selectNote}
              </Link>
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }
 
   return (
     <div className="min-h-screen bg-background flex flex-col">
      {/* Minimal header for zones - only theme/language, no navigation */}
      <header className="sticky top-0 z-[60] bg-card/95 backdrop-blur-sm border-b border-border shadow-sm">
        <div className="max-w-6xl mx-auto px-4 h-14 flex items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <Badge variant="outline" className="font-normal">
              <Lock className="h-3 w-3 mr-1" />
              {t.zoneView.sharedAccess}
            </Badge>
          </div>
          <div className="flex items-center gap-2">
            <LanguageSwitcher />
            <ThemeToggle />
          </div>
        </div>
      </header>
 
      {/* Edit header */}
      <div className="border-b bg-card/50 backdrop-blur-sm sticky top-14 z-10">
         <div className="container mx-auto px-4 py-3">
           <div className="flex items-center justify-between gap-4">
             <div className="flex items-center gap-3">
               <Button 
                 variant="ghost" 
                 size="icon"
                 asChild
               >
                 <Link to={`/zone/${zoneId}?code=${accessCode}`}>
                   <ArrowLeft className="h-4 w-4" />
                 </Link>
               </Button>
               <div>
                 <div className="flex items-center gap-2 text-sm text-muted-foreground">
                   <Badge variant="secondary" className="text-xs">
                     {t.zoneEdit?.editing || 'Editing'}
                   </Badge>
                   <span>•</span>
                   <span>{zone?.name}</span>
                 </div>
                 <h1 className="text-lg font-semibold truncate">{selectedNote.title}</h1>
               </div>
             </div>
             
             <div className="flex items-center gap-2">
               <span className="text-sm text-muted-foreground hidden sm:inline">
                 <Clock className="h-3 w-3 inline mr-1" />
                 {getTimeRemaining()}
               </span>
               <Button
                 onClick={handleSubmitProposal}
                 disabled={!hasChanges || isSubmitting}
               >
                 {isSubmitting ? (
                   <Loader2 className="h-4 w-4 animate-spin mr-2" />
                 ) : (
                   <Send className="h-4 w-4 mr-2" />
                 )}
                 {t.zoneEdit?.submitProposal || 'Submit Proposal'}
               </Button>
             </div>
           </div>
         </div>
      </div>
 
       {/* Main content */}
       <div className="container mx-auto px-4 py-6 flex-1">
         <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
           {/* Editor sidebar */}
           <aside className="lg:col-span-1">
             <Card>
               <CardHeader className="pb-3">
                 <CardTitle className="text-sm">
                   {t.zoneEdit?.yourDetails || 'Your Details'}
                 </CardTitle>
               </CardHeader>
               <CardContent className="space-y-4">
                 <div className="space-y-2">
                   <Label htmlFor="guestName">{t.zoneEdit?.name || 'Name'}</Label>
                   <Input
                     id="guestName"
                     value={guestName}
                     onChange={(e) => setGuestName(e.target.value)}
                     placeholder={t.zoneEdit?.namePlaceholder || 'Your name (optional)'}
                   />
                 </div>
                 <div className="space-y-2">
                   <Label htmlFor="guestEmail">{t.zoneEdit?.email || 'Email'}</Label>
                   <Input
                     id="guestEmail"
                     type="email"
                     value={guestEmail}
                     onChange={(e) => setGuestEmail(e.target.value)}
                     placeholder={t.zoneEdit?.emailPlaceholder || 'For notifications (optional)'}
                   />
                 </div>
                 
                 {selectedNote.tags.length > 0 && (
                   <div className="pt-4 border-t">
                     <p className="text-xs text-muted-foreground mb-2">{t.common?.tags || 'Tags'}</p>
                     <div className="flex flex-wrap gap-1">
                       {selectedNote.tags.map(tag => (
                         <Badge key={tag} variant="outline" className="text-xs">
                           #{tag}
                         </Badge>
                       ))}
                     </div>
                   </div>
                 )}
               </CardContent>
             </Card>
           </aside>
 
           {/* Editor */}
           <main className="lg:col-span-3">
             <Card className="h-full">
               <CardHeader className="pb-0">
                 <Tabs value={activeTab} onValueChange={(v) => setActiveTab(v as 'edit' | 'preview')}>
                   <TabsList>
                     <TabsTrigger value="edit">
                       <Edit3 className="h-4 w-4 mr-2" />
                       {t.editor?.edit || 'Edit'}
                     </TabsTrigger>
                     <TabsTrigger value="preview">
                       <Eye className="h-4 w-4 mr-2" />
                       {t.editor?.preview || 'Preview'}
                     </TabsTrigger>
                   </TabsList>
                 </Tabs>
               </CardHeader>
               <CardContent className="pt-4">
                 {activeTab === 'edit' ? (
                   <Textarea
                     value={editedContent}
                     onChange={(e) => setEditedContent(e.target.value)}
                     className="min-h-[60vh] font-mono text-sm resize-none"
                     placeholder={t.editor?.placeholder || 'Start writing...'}
                   />
                 ) : (
                   <div className="min-h-[60vh] prose-garden">
                     <ZoneNoteRenderer 
                       content={editedContent}
                       allowedSlugs={zone?.notes.map(n => n.slug) || []}
                       onNavigate={() => {}}
                     />
                   </div>
                 )}
               </CardContent>
             </Card>
           </main>
         </div>
       </div>
 
       {/* Changes indicator */}
       {hasChanges && (
         <div className="fixed bottom-4 left-1/2 -translate-x-1/2 z-50">
           <Badge className="bg-primary text-primary-foreground px-4 py-2 shadow-lg">
             <Save className="h-3 w-3 mr-2" />
             {t.zoneEdit?.unsavedChanges || 'You have unsaved changes'}
           </Badge>
         </div>
       )}
     </div>
   );
 }