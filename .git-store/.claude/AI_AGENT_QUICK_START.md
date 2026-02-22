# AI Agent Integration - Quick Start

## 🎯 Goal
Add "Request AI Summary" button to garden-bloom notes that creates AI-generated summaries via Garden-Agent-Service.

---

## ⚡ 5-Minute Implementation

### 1. Add Environment Variable

```bash
# .env.local
VITE_ORCHESTRATOR_URL=https://garden-orchestrator.maxfraieho.workers.dev
```

### 2. Create Hook

**File**: `src/hooks/useAgentTasks.ts`

```typescript
import { useState } from 'react';

interface AgentTask {
  id: string;
  task_type: string;
  role: string;
  status: 'pending' | 'in_progress' | 'completed' | 'failed';
  result?: { output: string; observation_id?: number };
}

const ORCHESTRATOR_URL = import.meta.env.VITE_ORCHESTRATOR_URL;

export function useAgentTasks() {
  const [tasks, setTasks] = useState<AgentTask[]>([]);

  const createTask = async (data: any): Promise<AgentTask> => {
    const response = await fetch(`${ORCHESTRATOR_URL}/tasks/`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    });
    const task = await response.json();
    setTasks(prev => [...prev, task]);
    return task;
  };

  const pollTaskStatus = async (taskId: string): Promise<AgentTask> => {
    const response = await fetch(`${ORCHESTRATOR_URL}/tasks/${taskId}`);
    const task = await response.json();
    setTasks(prev => prev.map(t => t.id === taskId ? task : t));
    return task;
  };

  return { tasks, createTask, pollTaskStatus };
}
```

### 3. Add Button to NotePage

**File**: `src/pages/NotePage.tsx`

```typescript
import { useAgentTasks } from '@/hooks/useAgentTasks';
import { Bot, Loader2 } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { useToast } from '@/hooks/use-toast';

// Inside NotePage component:
const { createComment } = useComments();
const { createTask, pollTaskStatus } = useAgentTasks();
const { toast } = useToast();
const [isGenerating, setIsGenerating] = useState(false);

const requestAISummary = async () => {
  setIsGenerating(true);

  try {
    // Create task
    const task = await createTask({
      task_type: 'summarize_article',
      role: 'archivist',
      input_data: {
        article_slugs: [note.slug],
        instructions: 'Create concise summary with key points',
        output_format: 'markdown'
      }
    });

    toast({
      title: "AI is reading your note...",
      description: "This may take 30-60 seconds"
    });

    // Poll for completion
    const checkStatus = async () => {
      const updated = await pollTaskStatus(task.id);

      if (updated.status === 'completed') {
        // Create AI comment
        await createComment({
          articleSlug: note.slug,
          author: {
            id: 'garden-agent-archivist',
            name: 'Garden Agent (Archivist)',
            domain: 'garden-agent-service.local',
            isOwner: false,
            type: 'ai-agent',
            agentModel: 'claude-sonnet-4-5'
          },
          content: updated.result!.output,
          status: 'pending'
        });

        setIsGenerating(false);
        toast({
          title: "AI summary created!",
          description: "Check comments section (requires approval)"
        });

      } else if (updated.status === 'failed') {
        setIsGenerating(false);
        toast({
          title: "Summary failed",
          description: "Worker may be offline",
          variant: "destructive"
        });
      } else {
        // Still processing, check again in 3 seconds
        setTimeout(checkStatus, 3000);
      }
    };

    checkStatus();

  } catch (error) {
    setIsGenerating(false);
    toast({
      title: "Error",
      description: "Failed to create task",
      variant: "destructive"
    });
  }
};

// Add button near comment section in JSX:
<div className="flex gap-2 mb-4">
  <Button
    variant="outline"
    onClick={requestAISummary}
    disabled={isGenerating}
  >
    {isGenerating ? (
      <>
        <Loader2 className="mr-2 h-4 w-4 animate-spin" />
        AI is reading...
      </>
    ) : (
      <>
        <Bot className="mr-2 h-4 w-4" />
        Request AI Summary
      </>
    )}
  </Button>
</div>
```

### 4. Update CommentItem for AI Badge

**File**: `src/components/garden/CommentItem.tsx`

```typescript
// Add AI badge in author section:
{comment.author.type === 'ai-agent' && (
  <span className="inline-flex items-center px-2 py-1 rounded-full text-xs bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-200">
    <Bot className="mr-1 h-3 w-3" />
    AI Agent
    {comment.author.agentModel && (
      <span className="ml-1 opacity-75">({comment.author.agentModel})</span>
    )}
  </span>
)}
```

---

## 🎬 User Flow

```
1. User opens note "My Thoughts on AI"
2. Clicks "Request AI Summary" button
3. Toast: "AI is reading your note..."
4. Button shows spinner: "AI is reading..."
5. After ~30s, toast: "AI summary created!"
6. Comment appears in comment section with purple "AI Agent" badge
7. Owner clicks "Approve" in comment moderation
8. Summary now visible to all visitors
```

---

## 🧪 Test

```bash
# 1. Check orchestrator is running
curl https://garden-orchestrator.maxfraieho.workers.dev/health

# 2. Check workers online
curl https://garden-orchestrator.maxfraieho.workers.dev/poll/workers

# 3. Create test task
curl -X POST https://garden-orchestrator.maxfraieho.workers.dev/tasks/ \
  -H "Content-Type: application/json" \
  -d '{
    "task_type": "summarize_article",
    "role": "archivist",
    "input_data": {
      "article_slugs": ["test"],
      "instructions": "Create summary",
      "output_format": "markdown"
    }
  }'
```

---

## 📋 Task Types

### Summarize Article
```typescript
{
  task_type: 'summarize_article',
  role: 'archivist',
  input_data: {
    article_slugs: ['note-slug'],
    instructions: 'Create concise summary',
    output_format: 'markdown'
  }
}
```

### Create Digest
```typescript
{
  task_type: 'create_digest',
  role: 'archivist',
  input_data: {
    folders: ['journal', 'notes'],
    time_period: 'last_7_days',
    instructions: 'Weekly digest with themes',
    output_format: 'markdown'
  }
}
```

### Generate Essay
```typescript
{
  task_type: 'generate_essay',
  role: 'archivist',
  input_data: {
    article_slugs: ['note1', 'note2', 'note3'],
    instructions: 'Synthesize into essay on AI ethics',
    output_format: 'markdown'
  }
}
```

---

## 🎨 Optional Enhancements

### Add AI Actions Panel
```typescript
// New route: /ai-assistant
// Component: src/components/garden/AIAgentPanel.tsx
// Shows: Recent tasks, stats, batch operations
```

### Batch Operations
```typescript
// Select multiple notes → "Summarize Selected" button
const handleBatchSummary = (slugs: string[]) => {
  createTask({
    task_type: 'create_digest',
    role: 'archivist',
    input_data: { article_slugs: slugs }
  });
};
```

### Scheduled Digests
```typescript
// Recurring task every Monday
// Creates weekly digest in "digests/" folder
```

---

## 🔧 Troubleshooting

**Button doesn't work?**
- Check console for CORS errors
- Verify `VITE_ORCHESTRATOR_URL` is set
- Check orchestrator health endpoint

**Task stuck at "pending"?**
- No workers online
- Check worker status: `curl .../poll/workers`
- Worker may have crashed - check Garden-Agent-Service logs

**No comment created?**
- Task failed (check task status)
- Comment API error (check network tab)
- Permission issue (verify useComments hook works)

---

## 📚 Full Documentation

See `GARDEN_AGENT_INTEGRATION.md` for:
- Complete architecture
- All API endpoints
- Advanced features
- Security considerations
- Future enhancements

---

**Ready to implement!** Start with adding the button, test with one note, then expand features. 🚀
