import { Link } from 'react-router-dom';
import { useOwnerAuth } from '@/hooks/useOwnerAuth';
import { useIsMobile } from '@/hooks/use-mobile';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
  DropdownMenuLabel,
} from '@/components/ui/dropdown-menu';
import { Settings, LogOut, HelpCircle, Shield, Link2 } from 'lucide-react';
import { useLocale } from '@/hooks/useLocale';

interface OwnerMenuProps {
  isCompact?: boolean;
}

export function OwnerMenu({ isCompact = false }: OwnerMenuProps) {
  const { isAuthenticated, isInitialized, logout } = useOwnerAuth();
  const { t } = useLocale();
  const isMobile = useIsMobile();

  // Don't show if not initialized
  if (!isInitialized || !isAuthenticated) return null;
  
  // On mobile, always use compact mode (icon only)
  const showBadge = !isCompact && !isMobile;

  return (
    <>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button 
            variant="outline" 
            size={showBadge ? "sm" : "icon"} 
            className="gap-2"
          >
            <Shield className="h-4 w-4 text-primary" />
            {showBadge && (
              <Badge variant="secondary" className="text-xs">
                Owner
              </Badge>
            )}
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-56">
          <DropdownMenuLabel className="flex items-center gap-2">
            <Shield className="h-4 w-4 text-primary" />
            <span>{t.owner?.menu || 'Owner Menu'}</span>
          </DropdownMenuLabel>
          <DropdownMenuSeparator />
          
          {/* Settings */}
          <DropdownMenuItem asChild>
            <Link to="/admin/settings" className="flex">
              <Settings className="mr-2 h-4 w-4" />
              <span>{t.owner?.settings || 'Settings'}</span>
            </Link>
          </DropdownMenuItem>

          {/* Zones */}
          <DropdownMenuItem asChild>
            <Link to="/admin/zones" className="flex">
              <Link2 className="mr-2 h-4 w-4" />
              <span>{t.owner?.zones || 'Access Zones'}</span>
            </Link>
          </DropdownMenuItem>

          <DropdownMenuSeparator />

          {/* Help & Support */}
          <DropdownMenuItem asChild>
            <a
              href="https://github.com/lovable-dev/garden-docs"
              target="_blank"
              rel="noopener noreferrer"
              className="flex"
            >
              <HelpCircle className="mr-2 h-4 w-4" />
              <span>{t.owner?.help || 'Help & Support'}</span>
            </a>
          </DropdownMenuItem>

          <DropdownMenuSeparator />

          {/* Logout */}
          <DropdownMenuItem
            onClick={logout}
            className="text-destructive focus:text-destructive"
          >
            <LogOut className="mr-2 h-4 w-4" />
            <span>{t.owner?.logout || 'Logout'}</span>
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
    </>
  );
}
