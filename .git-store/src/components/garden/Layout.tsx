import { ReactNode } from 'react';
import { GardenHeader } from './GardenHeader';
import { Sidebar } from './Sidebar';
import { GardenFooter } from './GardenFooter';

interface LayoutProps {
  children: ReactNode;
  hideSidebar?: boolean;
  hideFooter?: boolean;
}

export function Layout({ children, hideSidebar = false, hideFooter = false }: LayoutProps) {
  return (
    <div className="min-h-screen w-full bg-background flex flex-col">
      {/* Header */}
      <GardenHeader />
      
      {/* Main content with sidebar */}
      <div className="flex-1 flex min-w-0">
        {/* Sidebar */}
        {!hideSidebar && <Sidebar />}
        
        {/* Main content area */}
        <main className="flex-1 min-w-0">
          {children}
        </main>
      </div>
      
      {/* Footer */}
      {!hideFooter && <GardenFooter />}
    </div>
  );
}
