// src/hooks/useDrakonDiagram.ts

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { commitDrakonDiagram, deleteDrakonDiagram } from '@/lib/api/mcpGatewayClient';
import { useToast } from '@/hooks/use-toast';
import { useLocale } from '@/hooks/useLocale';
import type { StoredDrakonDiagram } from '@/lib/drakon/types';

export function useDrakonDiagram(folderSlug: string, diagramId: string) {
  return useQuery<StoredDrakonDiagram>({
    queryKey: ['drakon-diagram', folderSlug, diagramId],
    queryFn: async () => {
      const response = await fetch(
        `/site/notes/${folderSlug}/diagrams/${diagramId}.drakon.json`
      );
      if (!response.ok) throw new Error('Diagram not found');
      return response.json();
    },
    staleTime: 5 * 60 * 1000, // 5 minutes
  });
}

export function useSaveDrakonDiagram(folderSlug?: string) {
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const { t } = useLocale();

  return useMutation({
    mutationFn: async ({
      diagramId,
      diagram,
      name,
      isNew,
    }: {
      diagramId: string;
      diagram: object;
      name?: string;
      isNew?: boolean;
    }) => {
      return commitDrakonDiagram({
        folderSlug,
        diagramId,
        diagram,
        name,
        isNew,
      });
    },
    onSuccess: (result, variables) => {
      if (result.success) {
        queryClient.invalidateQueries({
          queryKey: ['drakon-diagram', folderSlug, variables.diagramId],
        });
        toast({
          title: t.editor?.saved || 'Diagram saved',
          description: 'Changes committed to repository.',
        });
      } else {
        throw new Error(result.error || 'Failed to save diagram');
      }
    },
    onError: (error) => {
      toast({
        title: t.editor?.error || 'Failed to save',
        description: error instanceof Error ? error.message : 'Unknown error',
        variant: 'destructive',
      });
    },
  });
}

export function useDeleteDrakonDiagram(folderSlug: string) {
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const { t } = useLocale();

  return useMutation({
    mutationFn: async (diagramId: string) => {
      return deleteDrakonDiagram(folderSlug, diagramId);
    },
    onSuccess: (result, diagramId) => {
      if (result.success) {
        queryClient.invalidateQueries({
          queryKey: ['drakon-diagram', folderSlug, diagramId],
        });
        toast({
          title: 'Diagram deleted',
        });
      } else {
        throw new Error(result.error || 'Failed to delete diagram');
      }
    },
    onError: (error) => {
      toast({
        title: t.editor?.error || 'Failed to delete',
        description: error instanceof Error ? error.message : 'Unknown error',
        variant: 'destructive',
      });
    },
  });
}
