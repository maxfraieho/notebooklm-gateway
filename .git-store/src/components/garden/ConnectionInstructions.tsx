// MCP Connection Instructions Modal

import { useState } from 'react';
import { Copy, Check, Monitor, Terminal, Globe } from 'lucide-react';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';

interface ConnectionInstructionsProps {
  sessionId: string;
  endpoint: string;
  isOpen: boolean;
  onClose: () => void;
}

function CopyBlock({ content, label }: { content: string; label: string }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(content);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <span className="text-sm font-medium">{label}</span>
        <Button variant="ghost" size="sm" onClick={handleCopy} className="gap-1">
          {copied ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
          {copied ? 'Скопійовано' : 'Копіювати'}
        </Button>
      </div>
      <pre className="bg-muted p-3 rounded-lg text-xs font-mono overflow-x-auto whitespace-pre-wrap break-all">
        {content}
      </pre>
    </div>
  );
}

export function ConnectionInstructions({
  sessionId,
  endpoint,
  isOpen,
  onClose,
}: ConnectionInstructionsProps) {
  const claudeDesktopConfig = JSON.stringify(
    {
      mcpServers: {
        'garden-mcp': {
          url: endpoint,
          transport: 'stdio',
        },
      },
    },
    null,
    2
  );

  const claudeCliCommand = `claude mcp add garden-mcp ${endpoint}`;
  const curlCommand = `curl -X GET "${endpoint}/tools"`;

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="max-w-2xl max-h-[80vh] overflow-hidden flex flex-col">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            📖 Інструкції підключення
          </DialogTitle>
          <DialogDescription>
            Оберіть метод підключення до MCP сесії
          </DialogDescription>
        </DialogHeader>

        <Tabs defaultValue="desktop" className="flex-1 overflow-hidden">
          <TabsList className="grid w-full grid-cols-3">
            <TabsTrigger value="desktop" className="gap-1">
              <Monitor className="w-4 h-4" />
              Desktop
            </TabsTrigger>
            <TabsTrigger value="cli" className="gap-1">
              <Terminal className="w-4 h-4" />
              CLI
            </TabsTrigger>
            <TabsTrigger value="api" className="gap-1">
              <Globe className="w-4 h-4" />
              HTTP API
            </TabsTrigger>
          </TabsList>

          <div className="mt-4 overflow-y-auto max-h-[50vh] space-y-4">
            {/* Claude Desktop */}
            <TabsContent value="desktop" className="space-y-4 m-0">
              <div className="space-y-2">
                <h4 className="font-medium">1. Знайдіть конфіг файл Claude Desktop</h4>
                <div className="text-sm text-muted-foreground space-y-1">
                  <p><strong>macOS:</strong> <code className="bg-muted px-1 rounded">~/Library/Application Support/Claude/claude_desktop_config.json</code></p>
                  <p><strong>Windows:</strong> <code className="bg-muted px-1 rounded">%APPDATA%\Claude\claude_desktop_config.json</code></p>
                  <p><strong>Linux:</strong> <code className="bg-muted px-1 rounded">~/.config/Claude/claude_desktop_config.json</code></p>
                </div>
              </div>

              <div className="space-y-2">
                <h4 className="font-medium">2. Додайте або оновіть конфігурацію</h4>
                <CopyBlock content={claudeDesktopConfig} label="Конфігурація JSON" />
              </div>

              <div className="space-y-2">
                <h4 className="font-medium">3. Перезапустіть Claude Desktop</h4>
                <p className="text-sm text-muted-foreground">
                  Після збереження файлу закрийте та відкрийте Claude Desktop знову.
                </p>
              </div>
            </TabsContent>

            {/* Claude CLI */}
            <TabsContent value="cli" className="space-y-4 m-0">
              <div className="space-y-2">
                <h4 className="font-medium">1. Переконайтесь, що Claude CLI встановлено</h4>
                <p className="text-sm text-muted-foreground">
                  Якщо ні, встановіть через <code className="bg-muted px-1 rounded">npm install -g @anthropic/claude-cli</code>
                </p>
              </div>

              <div className="space-y-2">
                <h4 className="font-medium">2. Додайте MCP сервер</h4>
                <CopyBlock content={claudeCliCommand} label="Команда CLI" />
              </div>

              <div className="space-y-2">
                <h4 className="font-medium">3. Використовуйте в чаті</h4>
                <p className="text-sm text-muted-foreground">
                  Тепер в Claude CLI доступні інструменти вашого Digital Garden.
                </p>
              </div>
            </TabsContent>

            {/* HTTP API */}
            <TabsContent value="api" className="space-y-4 m-0">
              <div className="space-y-2">
                <h4 className="font-medium">Доступні endpoints</h4>
                <div className="text-sm text-muted-foreground space-y-1">
                  <p><strong>GET /tools</strong> - Список доступних інструментів</p>
                  <p><strong>POST /execute</strong> - Виконання інструменту</p>
                </div>
              </div>

              <div className="space-y-2">
                <h4 className="font-medium">Приклад запиту</h4>
                <CopyBlock content={curlCommand} label="cURL команда" />
              </div>

              <div className="space-y-2">
                <h4 className="font-medium">Endpoint URL</h4>
                <CopyBlock content={endpoint} label="Base URL" />
              </div>
            </TabsContent>
          </div>
        </Tabs>

        <div className="pt-4 border-t">
          <Button onClick={onClose} className="w-full">
            Закрити
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
