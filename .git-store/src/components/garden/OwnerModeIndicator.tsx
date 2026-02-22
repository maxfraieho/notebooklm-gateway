import { useState } from 'react';
import { Link } from 'react-router-dom';
import { useOwnerAuth } from '@/hooks/useOwnerAuth';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { Shield, LogOut, Settings, Lock, Activity } from 'lucide-react';
import { OwnerLoginDialog } from './OwnerLoginDialog';
import { OwnerSettingsDialog } from './OwnerSettingsDialog';

export function OwnerModeIndicator() {
  const { isAuthenticated, isInitialized, logout, gatewayAvailable } = useOwnerAuth();
  const [showLogin, setShowLogin] = useState(false);
  const [showSettings, setShowSettings] = useState(false);

  // Don't show if not initialized (setup wizard will handle it)
  if (!isInitialized) return null;

  // If MCP gateway is unavailable, hide owner-mode UI entirely (public/read-only mode)
  if (!gatewayAvailable) return null;

  if (!isAuthenticated) {
    return (
      <>
        <Button
          variant="ghost"
          size="sm"
          onClick={() => setShowLogin(true)}
          className="gap-2"
        >
          <Lock className="h-4 w-4" />
          <span className="hidden sm:inline">Owner Login</span>
        </Button>
        <OwnerLoginDialog open={showLogin} onOpenChange={setShowLogin} />
      </>
    );
  }

  return (
    <>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="outline" size="sm" className="gap-2">
            <Shield className="h-4 w-4 text-primary" />
            <Badge variant="secondary" className="text-xs">
              Owner Mode
            </Badge>
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end">
          <DropdownMenuItem asChild>
            <Link to="/admin/diagnostics" className="flex items-center">
              <Activity className="mr-2 h-4 w-4" />
              Diagnostics
            </Link>
          </DropdownMenuItem>
          <DropdownMenuSeparator />
          <DropdownMenuItem onClick={() => setShowSettings(true)}>
            <Settings className="mr-2 h-4 w-4" />
            Settings
          </DropdownMenuItem>
          <DropdownMenuSeparator />
          <DropdownMenuItem onClick={logout} className="text-destructive">
            <LogOut className="mr-2 h-4 w-4" />
            Logout
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
      
      <OwnerSettingsDialog open={showSettings} onOpenChange={setShowSettings} />
    </>
  );
}
