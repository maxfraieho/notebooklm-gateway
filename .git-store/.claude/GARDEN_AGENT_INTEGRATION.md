# Garden Agent Service - Integration Guide for Lovable.dev

## 🎯 Overview

This document explains how **Garden-Agent-Service** works and how to integrate it into the **garden-bloom** UI to enable AI agent collaboration on Digital Garden content.

**Goal**: Allow Claude AI agents to interact with garden-bloom notes, create comments, annotations, and summaries through a dedicated orchestration service, appearing alongside human collaborators.

---

## 📐 Architecture Overview

### Current Setup

```
┌─────────────────────────────────────────────────────────────────┐
│                         GARDEN-BLOOM                            │
│                     (React + TypeScript)                        │
│                                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐         │
│  │   NoteView   │  │   Comments   │  │ Annotations  │         │
│  │              │  │              │  │              │         │
│  │  - Markdown  │  │  - Human     │  │  - Highlights│         │
│  │  - Wikilinks │  │  - AI Agent  │←─┼─ Comments   │         │
│  │  - Backlinks │  │  - Moderation│  │              │         │
│  └──────┬───────┘  └──────┬───────┘  └──────────────┘         │
│         │                  │                                    │
│         └──────────────────┼────────────────────────────────────┤
│                            ↓                                    │
│                  Cloudflare Worker Gateway                      │
│              (garden-mcp-server.maxfraieho...)                 │
└─────────────────────────────────────────────────────────────────┘
                            ↓
                            ↓ HTTP API (Comments, MCP Sessions)
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│              GARDEN-AGENT-SERVICE (NEW!)                        │
│                  (FastAPI + Python + uv)                        │
│           Location: /home/vokov/projects/Garden-Agent-Service   │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                 Task Orchestrator                        │  │
│  │  - Receives tasks from garden-bloom or external triggers │  │
│  │  - Queues tasks by priority                              │  │
│  │  - Assigns tasks to workers based on role requirements   │  │
│  └──────────────────────────────────────────────────────────┘  │
│                            ↓                                    │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │              Polling-Based Workers                       │  │
│  │                                                           │  │
│  │  Worker 1 (Raspberry Pi):                                │  │
│  │    ┌─────────────┐  ┌─────────────┐  ┌─────────────┐    │  │
│  │    │ Archivist   │  │ Tech Writer │  │ Architect   │    │  │
│  │    │             │  │             │  │             │    │  │
│  │    │ - Summarize │  │ - Create    │  │ - Analyze   │    │  │
│  │    │ - Digest    │  │   docs      │  │   structure │    │  │
│  │    │ - Essay     │  │ - API docs  │  │ - Review    │    │  │
│  │    │   from notes│  │ - README    │  │   taxonomy  │    │  │
│  │    └─────────────┘  └─────────────┘  └─────────────┘    │  │
│  │                                                           │  │
│  │  Worker 2, 3... (Future expansion)                       │  │
│  └──────────────────────────────────────────────────────────┘  │
│                            ↓                                    │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │            Claude-Mem Integration (NEW!)                 │  │
│  │  - Persistent memory across sessions                     │  │
│  │  - Context retrieval for task execution                  │  │
│  │  - Observation storage after task completion             │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                            ↓
                  Claude CLI (on worker machine)
                            ↓
                  Claude API (Anthropic)
```

---

## 🔧 How Garden-Agent-Service Works

### 1. **Task Creation Flow**

```
User action in garden-bloom
  ↓
POST /tasks/ {
  task_type: "summarize_article" | "create_digest" | "generate_essay",
  role: "archivist" | "technical_writer" | "architect",
  input_data: {
    article_slugs: ["note1", "note2"],
    instructions: "Create a weekly digest",
    output_format: "markdown"
  },
  context: {
    access_zone_id?: "zone-123",  // For restricted access
    target_folder?: "summaries"
  }
}
  ↓
Task Queue (in-memory, priority-based)
  ↓
Status: "pending"
```

### 2. **Worker Polling Flow**

```python
# worker.py (runs on Raspberry Pi or any machine)

while True:
    # 1. Heartbeat every 5 seconds
    POST /poll/heartbeat { worker_id: "rpi-1" }

    # 2. Poll for next task
    GET /poll/next?worker_id=rpi-1&roles=archivist,technical_writer

    # 3. If task available:
    task = response.json()["task"]

    # 4. Load context from claude-mem (NEW!)
    memory_context = get_memory_context(task)
    # Returns recent observations for this project:
    # - Previous summaries
    # - Patterns learned
    # - User preferences

    # 5. Execute via Claude CLI with context
    result = subprocess.run([
        "claude", "-p", f"""
        {ROLE_SYSTEM_PROMPT}

        {memory_context}  # Historical context

        ## Current Task
        {task.input_data}
        """
    ])

    # 6. Save result as observation (NEW!)
    obs_id = save_observation(
        project="Garden-Agent-Service",
        content=result.output,
        concepts=["summary", "digest", task.role]
    )

    # 7. Return result
    POST /poll/complete {
        task_id: task.id,
        status: "completed",
        result: {
            output: result.stdout,
            observation_id: obs_id  # Link to memory
        }
    }

    sleep(5)
```

### 3. **Memory Integration (Claude-Mem)**

**NEW FEATURE**: Garden-Agent-Service now uses claude-mem for persistent memory.

**Benefits:**
- Agents remember previous work across sessions
- Context-aware task execution (knows project history)
- Improved output quality (learns from patterns)
- Reduced repetition (recalls decisions)

**Example Context Retrieval:**
```python
# When task says "Create weekly digest like last time"
observations = adapter.get_recent_observations(
    project="Garden-Agent-Service",
    limit=10
)
# Returns:
# [
#   {type: "digest", text: "Weekly Digest #5: Format: H2 headings, 3 sections..."},
#   {type: "decision", text: "User prefers summaries in Ukrainian..."},
#   {type: "pattern", text: "Always include wikilinks [[like this]]..."}
# ]

context = format_context(observations)
# Agent receives this context in prompt, ensuring consistency
```

---

## 🎨 UI Integration Points in garden-bloom

### **Option 1: AI Agent Panel (Recommended)**

Add a new page/panel for AI-assisted operations:

**New Component: `AIAgentPanel.tsx`**

```typescript
// Location: src/components/garden/AIAgentPanel.tsx

import { useAgentTasks } from '@/hooks/useAgentTasks';

interface AgentTask {
  id: string;
  task_type: 'summarize_article' | 'create_digest' | 'generate_essay';
  role: 'archivist' | 'technical_writer' | 'architect';
  status: 'pending' | 'in_progress' | 'completed' | 'failed';
  result?: {
    output: string;
    observation_id?: number;
  };
  created_at: string;
  completed_at?: string;
}

export function AIAgentPanel() {
  const { tasks, createTask, pollTaskStatus } = useAgentTasks();

  const handleSummarizeArticle = async (slugs: string[]) => {
    const task = await createTask({
      task_type: 'summarize_article',
      role: 'archivist',
      input_data: {
        article_slugs: slugs,
        instructions: 'Create a concise summary with key points',
        output_format: 'markdown'
      }
    });

    // Poll for completion
    const interval = setInterval(async () => {
      const updated = await pollTaskStatus(task.id);
      if (updated.status === 'completed') {
        clearInterval(interval);
        // Display result as AI comment
        createAIComment(slugs[0], updated.result.output);
      }
    }, 3000);
  };

  return (
    <div className="ai-agent-panel">
      <h2>AI Agent Assistance</h2>

      <Card>
        <CardHeader>
          <CardTitle>Request AI Summary</CardTitle>
        </CardHeader>
        <CardContent>
          <Button onClick={() => handleSummarizeArticle([currentNote.slug])}>
            Summarize This Article
          </Button>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Recent Tasks</CardTitle>
        </CardHeader>
        <CardContent>
          {tasks.map(task => (
            <TaskItem key={task.id} task={task} />
          ))}
        </CardContent>
      </Card>
    </div>
  );
}
```

**New Hook: `useAgentTasks.ts`**

```typescript
// Location: src/hooks/useAgentTasks.ts

import { useState, useEffect } from 'react';

const ORCHESTRATOR_URL = import.meta.env.VITE_ORCHESTRATOR_URL ||
  'https://garden-orchestrator.maxfraieho.workers.dev';

export function useAgentTasks() {
  const [tasks, setTasks] = useState<AgentTask[]>([]);

  const createTask = async (taskData: CreateTaskRequest) => {
    const response = await fetch(`${ORCHESTRATOR_URL}/tasks/`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(taskData)
    });
    const task = await response.json();
    setTasks(prev => [...prev, task]);
    return task;
  };

  const pollTaskStatus = async (taskId: string) => {
    const response = await fetch(`${ORCHESTRATOR_URL}/tasks/${taskId}`);
    const updated = await response.json();
    setTasks(prev => prev.map(t => t.id === taskId ? updated : t));
    return updated;
  };

  const getTaskStats = async () => {
    const response = await fetch(`${ORCHESTRATOR_URL}/tasks/stats/queue`);
    return response.json();
  };

  return { tasks, createTask, pollTaskStatus, getTaskStats };
}
```

---

### **Option 2: Inline AI Actions**

Add AI action buttons directly in `NotePage.tsx`:

```typescript
// In NotePage.tsx, add near comment section

<div className="ai-actions">
  <Button
    variant="outline"
    onClick={() => requestAISummary(note.slug)}
  >
    <Bot className="mr-2 h-4 w-4" />
    Request AI Summary
  </Button>

  <Button
    variant="outline"
    onClick={() => requestAIEssay([note.slug, ...relatedNotes])}
  >
    <FileText className="mr-2 h-4 w-4" />
    Generate Essay from Related Notes
  </Button>
</div>

// When task completes, create AI comment:
const createAIComment = async (slug: string, content: string) => {
  await createComment({
    articleSlug: slug,
    author: {
      id: 'garden-agent-archivist',
      name: 'Garden Agent (Archivist)',
      domain: 'garden-agent-service.local',
      isOwner: false,
      type: 'ai-agent',  // Already supported!
      agentModel: 'claude-sonnet-4-5'
    },
    content: content,
    status: 'pending'  // Owner must approve
  });
};
```

---

### **Option 3: Scheduled Digest Generation**

Create automated weekly/monthly digests:

```typescript
// New component: DigestScheduler.tsx

export function DigestScheduler() {
  const [schedule, setSchedule] = useState({
    frequency: 'weekly',  // weekly, monthly
    dayOfWeek: 1,         // Monday
    folders: ['journal', 'notes'],
    role: 'archivist'
  });

  const scheduleDigest = async () => {
    // Create recurring task
    await createTask({
      task_type: 'create_digest',
      role: schedule.role,
      input_data: {
        folders: schedule.folders,
        time_period: schedule.frequency,
        instructions: 'Create a digest of recent notes with themes',
        output_format: 'markdown'
      },
      context: {
        recurring: true,
        schedule: schedule.frequency
      }
    });
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>Automated Digests</CardTitle>
      </CardHeader>
      <CardContent>
        <Select value={schedule.frequency} onValueChange={...}>
          <SelectItem value="weekly">Weekly</SelectItem>
          <SelectItem value="monthly">Monthly</SelectItem>
        </Select>
        <Button onClick={scheduleDigest}>Schedule Digest</Button>
      </CardContent>
    </Card>
  );
}
```

---

## 🔌 API Endpoints Reference

### Garden-Agent-Service Endpoints

**Base URL**: `https://garden-orchestrator.maxfraieho.workers.dev`

#### **Tasks API**

```typescript
// Create task
POST /tasks/
Body: {
  task_type: string;
  role: string;
  input_data: object;
  context?: object;
}
Response: Task

// Get task status
GET /tasks/{task_id}
Response: Task

// List tasks
GET /tasks/?status=pending&role=archivist
Response: Task[]

// Cancel task
DELETE /tasks/{task_id}
Response: { message: "Task cancelled" }

// Queue stats
GET /tasks/stats/queue
Response: {
  total_tasks: number;
  pending: number;
  in_progress: number;
  completed: number;
  failed: number;
  queue_depth: number;
}
```

#### **Worker Management** (For monitoring)

```typescript
// List active workers
GET /poll/workers
Response: Worker[]

// Worker stats
GET /poll/workers/{worker_id}
Response: {
  worker_id: string;
  capabilities: string[];
  status: 'active' | 'idle';
  last_heartbeat: string;
  tasks_completed: number;
}
```

---

## 🎭 Agent Roles & Capabilities

### **1. Archivist**
**Purpose**: Knowledge synthesis and summarization

**Capabilities:**
- Summarize single articles
- Create digests from multiple notes
- Generate essays synthesizing themes
- Extract key concepts
- Create reading lists

**Example Tasks:**
```typescript
{
  task_type: 'summarize_article',
  role: 'archivist',
  input_data: {
    article_slugs: ['my-note-on-ai'],
    instructions: 'Create 3-paragraph summary',
    output_format: 'markdown'
  }
}

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

### **2. Technical Writer**
**Purpose**: Documentation creation

**Capabilities:**
- Create README files
- Generate API documentation
- Write ADR (Architecture Decision Records)
- Explain code snippets
- Create tutorials

**Example Tasks:**
```typescript
{
  task_type: 'create_documentation',
  role: 'technical_writer',
  input_data: {
    target: 'README',
    source_notes: ['project-notes', 'architecture'],
    style: 'beginner-friendly',
    sections: ['overview', 'installation', 'usage']
  }
}
```

### **3. Architect**
**Purpose**: Structure analysis and recommendations

**Capabilities:**
- Analyze note taxonomy
- Review folder structure
- Suggest categorization improvements
- Identify orphaned notes
- Recommend tag usage

**Example Tasks:**
```typescript
{
  task_type: 'analyze_structure',
  role: 'architect',
  input_data: {
    folders: ['all'],
    focus: 'taxonomy',
    recommendations: true
  }
}
```

---

## 🚀 Integration Implementation Steps

### **Phase 1: Basic Integration** (1-2 days)

1. **Add Environment Variable**
   ```
   # .env.local
   VITE_ORCHESTRATOR_URL=https://garden-orchestrator.maxfraieho.workers.dev
   ```

2. **Create Hook** (`src/hooks/useAgentTasks.ts`)
   - Implement `createTask`, `pollTaskStatus`, `getTaskStats`

3. **Add UI Component** (`src/components/garden/AIAgentPanel.tsx`)
   - Simple panel with "Request Summary" button
   - Task list with status

4. **Integrate in Existing Page**
   - Add to `NotePage.tsx` as collapsible section
   - Or create new route `/ai-assistant`

5. **Test Task Creation**
   - Click button → Creates task
   - Poll status → Shows "completed"
   - Display result in UI

### **Phase 2: Comment Integration** (1 day)

1. **Modify `useComments.ts`**
   - Add `createAIComment` function
   - Support `type: 'ai-agent'` author

2. **Update `CommentItem.tsx`**
   - Display AI agent badge
   - Show model name (claude-sonnet-4-5)
   - Different styling for AI comments

3. **Auto-create Comments**
   - When task completes → Create comment with output
   - Link to original task for tracking

### **Phase 3: Advanced Features** (2-3 days)

1. **Digest Scheduler**
   - Component for scheduling recurring digests
   - Store schedules in localStorage or backend

2. **Batch Operations**
   - Select multiple notes → Request batch summary
   - Create digest from selected folder

3. **Task History**
   - Page showing all past AI tasks
   - Filter by role, status, date

4. **AI Settings**
   - User preferences for AI behavior
   - Default prompts/instructions
   - Output format preferences

---

## 📊 Example User Flows

### **Flow 1: Summarize Article**

```
User opens note "My Thoughts on AI"
  ↓
Sees "Request AI Summary" button
  ↓
Clicks button
  ↓
garden-bloom → POST /tasks/ {
  task_type: "summarize_article",
  role: "archivist",
  input_data: { article_slugs: ["my-thoughts-on-ai"] }
}
  ↓
Task ID: task-123, Status: pending
  ↓
UI shows spinner "AI is reading your note..."
  ↓
Worker polls → Gets task-123 → Executes via Claude CLI
  ↓
Worker loads context from claude-mem (past summaries style)
  ↓
Claude generates summary
  ↓
Worker → POST /poll/complete { result: { output: "## Summary\n..." } }
  ↓
garden-bloom polls → Status: completed
  ↓
Creates AI comment with summary
  ↓
CommentSection shows:
  ┌────────────────────────────────────┐
  │ 🤖 Garden Agent (Archivist)        │
  │ claude-sonnet-4-5                  │
  │                                    │
  │ ## Summary                         │
  │ This note explores...              │
  │                                    │
  │ [Approve] [Reject]  [Edit]         │
  └────────────────────────────────────┘
  ↓
User approves → Comment becomes visible to guests
```

### **Flow 2: Weekly Digest**

```
User navigates to AI Assistant panel
  ↓
Clicks "Generate Weekly Digest"
  ↓
Selects folders: ["journal", "notes", "ideas"]
  ↓
garden-bloom → POST /tasks/ {
  task_type: "create_digest",
  role: "archivist",
  input_data: {
    folders: ["journal", "notes", "ideas"],
    time_period: "last_7_days"
  }
}
  ↓
Worker executes → Reads all notes from last 7 days
  ↓
Loads context: "Last digest format: H2 per theme, bullet points..."
  ↓
Claude generates digest with themes, key highlights, wikilinks
  ↓
Result saved → garden-bloom creates new note in "digests/" folder
  ↓
User receives notification: "Weekly digest created: [[digests/week-3-2026]]"
```

---

## 🔐 Security & Access Control

### **Access Zones Integration**

Garden-Agent-Service can use garden-bloom's access zones for restricted access:

```typescript
// When creating task for restricted folders:
const task = await createTask({
  task_type: 'summarize_article',
  role: 'archivist',
  input_data: { article_slugs: ['private-note'] },
  context: {
    access_zone_id: 'zone-123',  // Worker will use this zone's credentials
    access_code: 'abc123'
  }
});

// Worker validates access before reading notes:
GET /zone/zone-123?code=abc123
  → Returns allowed notes
  → Worker only processes allowed notes
```

### **Owner Approval Flow**

All AI-generated content requires owner approval:

1. Task completes → Creates comment with `status: 'pending'`
2. Owner sees in moderation queue
3. Owner can:
   - **Approve**: Comment becomes visible
   - **Reject**: Comment hidden
   - **Edit**: Modify before approving
   - **Merge**: Incorporate into note content

---

## 🧪 Testing the Integration

### **1. Health Check**

```bash
# Verify orchestrator is running
curl https://garden-orchestrator.maxfraieho.workers.dev/health

# Check worker availability
curl https://garden-orchestrator.maxfraieho.workers.dev/poll/workers
```

### **2. Create Test Task**

```bash
curl -X POST https://garden-orchestrator.maxfraieho.workers.dev/tasks/ \
  -H "Content-Type: application/json" \
  -d '{
    "task_type": "summarize_article",
    "role": "archivist",
    "input_data": {
      "article_slugs": ["test-note"],
      "instructions": "Create brief summary",
      "output_format": "markdown"
    }
  }'

# Response: { "id": "task-123", "status": "pending", ... }
```

### **3. Poll Status**

```bash
curl https://garden-orchestrator.maxfraieho.workers.dev/tasks/task-123

# When completed:
# {
#   "id": "task-123",
#   "status": "completed",
#   "result": {
#     "output": "## Summary\nThis note discusses...",
#     "observation_id": 42
#   }
# }
```

---

## 🎯 Recommended First Implementation

**Quick Win: Add "Request AI Summary" button to NotePage**

```typescript
// src/pages/NotePage.tsx

import { useAgentTasks } from '@/hooks/useAgentTasks';
import { Bot } from 'lucide-react';

export function NotePage() {
  const { note } = useNote();
  const { createComment } = useComments();
  const { createTask, pollTaskStatus } = useAgentTasks();
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

      // Poll for completion
      const checkStatus = async () => {
        const updated = await pollTaskStatus(task.id);

        if (updated.status === 'completed') {
          // Create AI comment
          await createComment({
            articleSlug: note.slug,
            author: {
              id: 'garden-agent',
              name: 'Garden Agent (Archivist)',
              domain: 'garden-agent-service',
              isOwner: false,
              type: 'ai-agent',
              agentModel: 'claude-sonnet-4-5'
            },
            content: updated.result.output,
            status: 'pending'
          });

          setIsGenerating(false);
        } else if (updated.status === 'failed') {
          setIsGenerating(false);
          toast.error('AI summary failed');
        } else {
          // Poll again in 3 seconds
          setTimeout(checkStatus, 3000);
        }
      };

      checkStatus();

    } catch (error) {
      setIsGenerating(false);
      toast.error('Failed to request summary');
    }
  };

  return (
    <div className="note-page">
      {/* Existing content */}

      <div className="ai-actions mt-4">
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

      <CommentSection slug={note.slug} />
    </div>
  );
}
```

**Result:** User clicks button → AI reads note → Creates summary comment → Owner approves → Summary visible to all

---

## 📚 Additional Resources

### **Garden-Agent-Service Documentation**

- **Location**: `/home/vokov/projects/Garden-Agent-Service/`
- **Key Files**:
  - `CLAUDE.md` - Development guide
  - `README.md` - API documentation
  - `worker.py` - Worker implementation with claude-mem
  - `src/api/tasks.py` - Task API endpoints
  - `src/services/claude_mem_adapter.py` - Memory integration

### **Claude-Mem Integration**

- **Plugin enabled**: `claude-mem@thedotmack` in both projects
- **Database**: `~/.claude-mem/claude-mem.db`
- **Benefits**: Agents remember context across sessions
- **Usage**: Automatic - workers load context before task execution

### **Testing Endpoints**

```bash
# Orchestrator health
curl https://garden-orchestrator.maxfraieho.workers.dev/health

# Task stats
curl https://garden-orchestrator.maxfraieho.workers.dev/tasks/stats/queue

# Active workers
curl https://garden-orchestrator.maxfraieho.workers.dev/poll/workers
```

---

## 💡 Future Enhancements

1. **Real-time Updates**: WebSocket connection for task status
2. **AI Annotations**: Agent highlights important passages
3. **Smart Linking**: Agent suggests wikilinks between notes
4. **Sentiment Analysis**: Tag notes with detected emotions/themes
5. **Translation**: Agent translates notes between supported languages
6. **Question Answering**: Chat interface for asking about note collection
7. **Knowledge Graph Insights**: Agent analyzes connection patterns

---

## ❓ FAQ for Lovable.dev Agent

**Q: Do I need to modify the backend (Cloudflare Worker)?**
A: No! Garden-Agent-Service is independent. Only add frontend UI to create tasks and display results.

**Q: How do users authenticate with Garden-Agent-Service?**
A: Currently no auth required. For production, can use garden-bloom's JWT token.

**Q: Can multiple workers execute tasks in parallel?**
A: Yes! Workers poll independently. Multiple tasks can run simultaneously.

**Q: What if worker is offline?**
A: Tasks queue up until worker comes online. UI shows "pending" status.

**Q: How to handle long-running tasks?**
A: Use polling with exponential backoff. Consider WebSocket for real-time updates.

**Q: Can I customize AI prompts?**
A: Yes! Pass custom `instructions` in `input_data`. Worker includes them in Claude prompt.

**Q: Does this work with access zones?**
A: Yes! Pass `access_zone_id` in task context. Worker validates before accessing notes.

**Q: How to display AI comments differently?**
A: Check `author.type === 'ai-agent'` in `CommentItem.tsx`, apply different styling/badge.

---

## ✅ Integration Checklist

- [ ] Add `VITE_ORCHESTRATOR_URL` environment variable
- [ ] Create `useAgentTasks.ts` hook
- [ ] Add "Request AI Summary" button to NotePage
- [ ] Implement task polling with status updates
- [ ] Create AI comment when task completes
- [ ] Update CommentItem to display AI badge
- [ ] Add AI actions panel to navigation (optional)
- [ ] Implement digest scheduler (optional)
- [ ] Add task history page (optional)
- [ ] Test with real note summarization
- [ ] Document for users in help/docs section

---

**Contact**: If questions arise during implementation, check Garden-Agent-Service CLAUDE.md or test endpoints directly.

**Deployment**: Garden-Agent-Service orchestrator already deployed at `garden-orchestrator.maxfraieho.workers.dev`. Worker running on Raspberry Pi with claude-mem integration.

Ready to enhance garden-bloom with AI agent collaboration! 🚀🌱
