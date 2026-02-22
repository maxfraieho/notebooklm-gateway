import { useMemo, useState } from 'react';
import { z } from 'zod';
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';

const schema = z.object({
  title: z.string().trim().min(1, 'Title is required').max(80, 'Max 80 chars'),
  notebookUrl: z.string().trim().url('Must be a valid URL'),
});

export function NewNotebookLMChatDialog(props: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  initialNotebookUrl?: string;
  onCreate: (data: { title: string; notebookUrl: string }) => void;
}) {
  const [title, setTitle] = useState('');
  const [notebookUrl, setNotebookUrl] = useState(props.initialNotebookUrl ?? '');
  const [touched, setTouched] = useState(false);

  const errors = useMemo(() => {
    if (!touched) return null;
    const res = schema.safeParse({ title, notebookUrl });
    if (res.success) return null;
    const map: Record<string, string> = {};
    for (const issue of res.error.issues) {
      const key = issue.path[0] as string;
      map[key] = issue.message;
    }
    return map;
  }, [title, notebookUrl, touched]);

  return (
    <Dialog
      open={props.open}
      onOpenChange={(open) => {
        props.onOpenChange(open);
        if (!open) {
          setTouched(false);
          setTitle('');
          setNotebookUrl(props.initialNotebookUrl ?? '');
        }
      }}
    >
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>New NotebookLM chat</DialogTitle>
        </DialogHeader>

        <div className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="nlm-title">Title</Label>
            <Input
              id="nlm-title"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              onBlur={() => setTouched(true)}
              placeholder="e.g. Replit backend test 6"
            />
            {errors?.title && <p className="text-xs text-destructive">{errors.title}</p>}
          </div>

          <div className="space-y-2">
            <Label htmlFor="nlm-url">Notebook URL</Label>
            <Input
              id="nlm-url"
              value={notebookUrl}
              onChange={(e) => setNotebookUrl(e.target.value)}
              onBlur={() => setTouched(true)}
              placeholder="https://notebooklm.google.com/notebook/..."
            />
            {errors?.notebookUrl && <p className="text-xs text-destructive">{errors.notebookUrl}</p>}
          </div>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => props.onOpenChange(false)}>
            Cancel
          </Button>
          <Button
            onClick={() => {
              setTouched(true);
              try {
                const data = schema.parse({ title, notebookUrl }) as { title: string; notebookUrl: string };
                props.onCreate(data);
                props.onOpenChange(false);
              } catch {
                // validation errors are shown inline
              }
            }}
          >
            Create
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
