import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import { SearchHighlightProvider } from "@/hooks/useSearchHighlight";
import { LocaleProvider } from "@/hooks/useLocale";
import { ThemeProvider } from "@/components/theme-provider";
import { OwnerAuthProvider, useOwnerAuth } from "@/hooks/useOwnerAuth.tsx";
import { OwnerSetupWizard } from "@/components/garden/OwnerSetupWizard";
import { AccessGuard } from "@/components/AccessGuard";
import Index from "./pages/Index";
import NotePage from "./pages/NotePage";
import TagPage from "./pages/TagPage";
import TagsIndex from "./pages/TagsIndex";
import GraphPage from "./pages/GraphPage";
import FilesPage from "./pages/FilesPage";
import ZoneViewPage from "./pages/ZoneViewPage";
import ZoneEditPage from "./pages/ZoneEditPage";
import ChatPage from "./pages/ChatPage";
import AdminDiagnosticsPage from "./pages/AdminDiagnosticsPage";
import AdminZonesPage from "./pages/AdminZonesPage";
import AdminSettingsPage from "./pages/AdminSettingsPage";
import PolicyPage from "./pages/PolicyPage";
import NotFound from "./pages/NotFound";
import EditorPage from "./pages/EditorPage";
import DrakonPage from "./pages/DrakonPage";
import { Loader2 } from "lucide-react";

const queryClient = new QueryClient();

function AppContent() {
  const { isInitialized, isLoading } = useOwnerAuth();

  // Show loading while checking auth status
  if (isLoading) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
      </div>
    );
  }

  // Show setup wizard if not initialized
  if (!isInitialized) {
    return <OwnerSetupWizard />;
  }

  // Normal app
  return (
    <BrowserRouter>
      <AccessGuard>
        <SearchHighlightProvider>
          <Routes>
            <Route path="/" element={<Index />} />
            <Route path="/notes/*" element={<NotePage />} />
            <Route path="/notes/:slug/edit" element={<EditorPage />} />
            <Route path="/notes/new" element={<EditorPage />} />
            <Route path="/drakon" element={<DrakonPage />} />
            <Route path="/tags" element={<TagsIndex />} />
            <Route path="/tags/:tag" element={<TagPage />} />
            <Route path="/graph" element={<GraphPage />} />
            <Route path="/files" element={<FilesPage />} />
            <Route path="/zone/:zoneId" element={<ZoneViewPage />} />
            <Route path="/zone/:zoneId/edit/:noteSlug" element={<ZoneEditPage />} />
            <Route path="/chat" element={<ChatPage />} />
            <Route path="/admin/diagnostics" element={<AdminDiagnosticsPage />} />
            <Route path="/admin/zones" element={<AdminZonesPage />} />
            <Route path="/admin/settings" element={<AdminSettingsPage />} />
            <Route path="/policy/delegated-zone-confidentiality" element={<PolicyPage />} />
            {/* ADD ALL CUSTOM ROUTES ABOVE THE CATCH-ALL "*" ROUTE */}
            <Route path="*" element={<NotFound />} />
          </Routes>
        </SearchHighlightProvider>
      </AccessGuard>
    </BrowserRouter>
  );
}

const App = () => (
  <QueryClientProvider client={queryClient}>
    <ThemeProvider defaultTheme="system" storageKey="garden-ui-theme">
      <LocaleProvider>
        <OwnerAuthProvider>
          <TooltipProvider>
            <Toaster />
            <Sonner />
            <AppContent />
          </TooltipProvider>
        </OwnerAuthProvider>
      </LocaleProvider>
    </ThemeProvider>
  </QueryClientProvider>
);

export default App;
