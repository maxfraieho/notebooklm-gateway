import { useParams, Link } from 'react-router-dom';
import { useState, useEffect } from 'react';
import { getNoteBySlug } from '@/lib/notes/noteLoader';
import { NoteLayout } from '@/components/garden/NoteLayout';
import { GardenHeader } from '@/components/garden/GardenHeader';
import { GardenFooter } from '@/components/garden/GardenFooter';
import { useLocale } from '@/hooks/useLocale';
import { ArrowLeft, FileQuestion, Clock, Loader2 } from 'lucide-react';
import { getGitStatus } from '@/lib/api/mcpGatewayClient';

export default function NotePage() {
  const { '*': slug } = useParams();
  const { t } = useLocale();
  const note = slug ? getNoteBySlug(slug) : null;
  
  const [isPending, setIsPending] = useState(false);
  const [isChecking, setIsChecking] = useState(!note && !!slug);

  // Check if note exists in GitHub but not in local bundle
  useEffect(() => {
    if (note || !slug) {
      setIsChecking(false);
      return;
    }

    const checkGitHubStatus = async () => {
      try {
        const path = `src/site/notes/${slug}.md`;
        const data = await getGitStatus(path);
        if (data.exists) {
          setIsPending(true);
        }
      } catch (err) {
        console.warn('Failed to check GitHub status:', err);
      } finally {
        setIsChecking(false);
      }
    };

    checkGitHubStatus();
  }, [slug, note]);

  const decodedSlug = slug ? decodeURIComponent(slug) : '';

  // Loading state while checking GitHub
  if (isChecking) {
    return (
      <div className="min-h-screen bg-background flex flex-col">
        <GardenHeader />
        <main className="flex-1 flex items-center justify-center">
          <div className="text-center px-6 animate-fade-in">
            <Loader2 className="w-12 h-12 text-muted-foreground mx-auto mb-4 animate-spin" />
            <p className="text-muted-foreground">...</p>
          </div>
        </main>
        <GardenFooter />
      </div>
    );
  }

  // Note exists in GitHub but pending sync to site
  if (!note && isPending) {
    return (
      <div className="min-h-screen bg-background flex flex-col">
        <GardenHeader />
        <main className="flex-1 flex items-center justify-center">
          <div className="text-center px-6 animate-fade-in max-w-md">
            <div className="w-16 h-16 rounded-full bg-primary/10 flex items-center justify-center mx-auto mb-6">
              <Clock className="w-8 h-8 text-primary" />
            </div>
            <h1 className="text-2xl font-semibold text-foreground mb-2 font-sans">
              {t.notePage.pendingTitle}
            </h1>
            <p className="text-muted-foreground mb-6">
              {t.notePage.pendingMessage.replace('{slug}', decodedSlug)}
            </p>
            <Link
              to="/"
              className="inline-flex items-center gap-2 text-primary hover:text-primary/80 transition-colors font-sans"
            >
              <ArrowLeft className="w-4 h-4" />
              {t.notePage.returnToGarden}
            </Link>
          </div>
        </main>
        <GardenFooter />
      </div>
    );
  }

  // Note not found anywhere
  if (!note) {
    return (
      <div className="min-h-screen bg-background flex flex-col">
        <GardenHeader />
        <main className="flex-1 flex items-center justify-center">
          <div className="text-center px-6 animate-fade-in">
            <FileQuestion className="w-16 h-16 text-muted-foreground mx-auto mb-6" />
            <h1 className="text-2xl font-semibold text-foreground mb-2 font-sans">
              {t.notePage.notFoundTitle}
            </h1>
            <p className="text-muted-foreground mb-6 max-w-md">
              {t.notePage.notFoundMessage.replace('{slug}', decodedSlug)}
            </p>
            <Link
              to="/"
              className="inline-flex items-center gap-2 text-primary hover:text-primary/80 transition-colors font-sans"
            >
              <ArrowLeft className="w-4 h-4" />
              {t.notePage.returnToGarden}
            </Link>
          </div>
        </main>
        <GardenFooter />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background flex flex-col">
      <GardenHeader />
      <main className="flex-1">
        <NoteLayout note={note} />
      </main>
      <GardenFooter />
    </div>
  );
}
