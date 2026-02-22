import { Layout } from '@/components/garden/Layout';
import { ChatCanvas } from '@/components/garden/ChatCanvas';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { NotebookLMChatTab } from '@/components/notebooklm/NotebookLMChatTab';
import { AccessZonesWall } from '@/components/garden/AccessZonesWall';
import { ProposalsInbox } from '@/components/garden/ProposalsInbox';

export default function ChatPage() {
  return (
    <Layout>
      <div className="container py-6">
        <div className="max-w-6xl mx-auto min-h-[calc(100vh-200px)]">
          <Tabs defaultValue="people" className="h-full flex flex-col">
            <TabsList className="w-fit">
              <TabsTrigger value="people">People</TabsTrigger>
              <TabsTrigger value="notebooklm">NotebookLM</TabsTrigger>
            </TabsList>

            <TabsContent value="people" className="flex-1 mt-4">
              <div className="h-full grid grid-cols-1 lg:grid-cols-[1fr_340px_300px] gap-4">
                <ChatCanvas title="💬 Colleagues Chat" className="h-full" />
                <AccessZonesWall className="h-full" />
                <ProposalsInbox className="h-full" />
              </div>
            </TabsContent>

            <TabsContent value="notebooklm" className="flex-1 mt-4">
              <NotebookLMChatTab className="h-full" />
            </TabsContent>
          </Tabs>
        </div>
      </div>
    </Layout>
  );
}
