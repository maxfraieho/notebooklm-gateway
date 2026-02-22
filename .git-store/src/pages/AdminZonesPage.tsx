import { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Loader2 } from 'lucide-react';
import { useOwnerAuth } from '@/hooks/useOwnerAuth';
import { Layout } from '@/components/garden/Layout';
import { AccessZonesManager } from '@/components/garden/AccessZonesManager';

export default function AdminZonesPage() {
  const { isAuthenticated, isLoading: authLoading } = useOwnerAuth();
  const navigate = useNavigate();

  // Redirect if not authenticated
  useEffect(() => {
    if (!authLoading && !isAuthenticated) {
      navigate('/');
    }
  }, [isAuthenticated, authLoading, navigate]);

  if (authLoading) {
    return (
      <Layout>
        <div className="min-h-screen flex items-center justify-center">
          <Loader2 className="h-8 w-8 animate-spin text-primary" />
        </div>
      </Layout>
    );
  }

  if (!isAuthenticated) {
    return null;
  }

  return (
    <Layout>
      <div className="max-w-4xl mx-auto px-4 py-8">
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-foreground mb-2">
            Access Zones
          </h1>
          <p className="text-muted-foreground">
            Manage delegated access to your garden with expiring links and folder restrictions.
          </p>
        </div>

        <AccessZonesManager />
      </div>
    </Layout>
  );
}
