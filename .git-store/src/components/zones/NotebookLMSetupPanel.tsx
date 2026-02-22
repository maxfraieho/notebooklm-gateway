import { useEffect, useMemo, useRef, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Progress } from '@/components/ui/progress';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { ExternalLink, RotateCcw, TriangleAlert } from 'lucide-react';
import type { ApiError, NotebookLMJobStatus, NotebookLMMapping } from '@/types/mcpGateway';
import {
  getNotebookLMJobStatus,
  getZoneNotebookLMStatus,
  retryNotebookLMImport,
} from '@/lib/api/mcpGatewayClient';
import { cn } from '@/lib/utils';

type Props = {
  zoneId: string;
  initialNotebooklm?: NotebookLMMapping | null;
  isOwner: boolean;
};

const HARD_TIMEOUT_MS = 15 * 60 * 1000;
const MAX_RETRIES = 3;
const BASE_DELAY = 2000;

function getErrorMessage(error: any): string {
  if (error?.code === 'NOT_AUTHENTICATED' || error?.errorCode === 'NOT_AUTHENTICATED') {
    return 'NotebookLM не авторизовано. Зверніться до адміністратора.';
  }

  if (error?.code === 'NOTEBOOKLM_ERROR' || error?.errorCode === 'NOTEBOOKLM_ERROR') {
    return 'Помилка сервісу NotebookLM. Спробуйте пізніше.';
  }

  const status = error?.httpStatus ?? error?.status;
  if (status === 502 || status === 504) {
    return 'NotebookLM тимчасово недоступний. Спробуйте через кілька хвилин.';
  }

  if (typeof error?.message === 'string' && error.message.includes('FileNotFoundError')) {
    return 'NotebookLM backend не налаштований (відсутній браузер або cookies). Зверніться до адміністратора.';
  }

  return error?.message || 'Сталася невідома помилка.';
}

function isConfigError(error: any): boolean {
  if (!error) return false;
  if (error?.code === 'NOT_AUTHENTICATED' || error?.errorCode === 'NOT_AUTHENTICATED') return true;
  if (typeof error?.message === 'string' && error.message.includes('FileNotFoundError')) return true;
  return false;
}

function getStageText(
  opts: {
    job?: NotebookLMJobStatus;
    isLoading: boolean;
    timedOut: boolean;
  }
): string | null {
  const { job, isLoading, timedOut } = opts;
  if (timedOut) return 'Імпорт триває довше ніж очікувалось…';
  if (isLoading && !job) return 'Перевірка підключення до NotebookLM…';

  if (job?.current_step && job?.total_steps) {
    return `Імпорт джерел (${job.current_step}/${job.total_steps})…`;
  }

  switch (job?.status) {
    case 'queued':
      return 'Очікування в черзі…';
    case 'created':
      return 'Створення блокнота…';
    case 'pending':
    case 'running':
      return 'Імпорт джерел…';
    case 'completed':
      return 'Завершення імпорту…';
    case 'failed':
      return 'Помилка імпорту';
    default:
      return job?.status ? `Статус: ${job.status}` : null;
  }
}

function computeProgress(job: NotebookLMJobStatus | undefined): number {
  if (!job) return 0;
  if (typeof job.progress === 'number') return Math.max(0, Math.min(100, job.progress));
  if (job.current_step && job.total_steps) {
    return Math.max(0, Math.min(100, Math.round((job.current_step / job.total_steps) * 100)));
  }
  return 12;
}

function stopPollingFor(job: NotebookLMJobStatus | undefined): boolean {
  if (!job) return false;
  return job.status === 'completed' || job.status === 'failed';
}

function hasMinioLocalhostFailure(job: NotebookLMJobStatus | undefined): boolean {
  const results = job?.results;
  if (!Array.isArray(results)) return false;
  return results.some((r) => typeof r?.error === 'string' && r.error.includes("host='localhost'") && r.error.includes('port=9000'));
}

function formatSourceLabel(r: NonNullable<NonNullable<NotebookLMJobStatus['results']>[number]>): string {
  const key = r?.source?.key;
  const url = r?.source?.url;
  if (typeof key === 'string' && key.trim()) return key;
  if (typeof url === 'string' && url.trim()) return url;
  return 'source';
}

export function NotebookLMSetupPanel({ zoneId, initialNotebooklm, isOwner }: Props) {
  const [mapping, setMapping] = useState<NotebookLMMapping | null>(initialNotebooklm ?? null);
  const [backoffMs, setBackoffMs] = useState(2500);
  const [timedOut, setTimedOut] = useState(false);
  const startedAtRef = useRef<number>(Date.now());

  // Source of truth: zone notebooklm mapping
  const mappingQuery = useQuery({
    queryKey: ['notebooklm-mapping', zoneId],
    queryFn: () => getZoneNotebookLMStatus(zoneId),
    enabled: !mapping,
    staleTime: 5_000,
  });

  useEffect(() => {
    if (mappingQuery.data?.notebooklm !== undefined) {
      setMapping(mappingQuery.data.notebooklm);
    }
  }, [mappingQuery.data]);

  const jobId = mapping?.importJobId ?? null;

  const jobQuery = useQuery({
    queryKey: ['notebooklm-job', zoneId, jobId],
    queryFn: () => getNotebookLMJobStatus(zoneId, jobId as string),
    enabled: !!jobId && !timedOut,
    refetchInterval: (query) => {
      if (!jobId) return false;
      const data = query.state.data as NotebookLMJobStatus | undefined;
      if (stopPollingFor(data)) return false;
      return backoffMs;
    },
    retry: (failureCount, error) => {
      const e = error as ApiError | any;
      const status = e?.httpStatus ?? e?.status;
      const isTransient = status === 502 || status === 504;
      if (!isTransient) return false;
      return failureCount < MAX_RETRIES;
    },
    retryDelay: (attemptIndex) => BASE_DELAY * (attemptIndex + 1),
  });

  // Backoff on network-ish errors
  useEffect(() => {
    if (!jobQuery.isError) return;
    const e = jobQuery.error as ApiError | any;
    const status = e?.httpStatus ?? e?.status;
    const isTransient = status === 502 || status === 504;
    if (!isTransient) return;
    setBackoffMs((prev) => Math.min(30_000, prev * 2));
  }, [jobQuery.isError]);

  // Hard timeout
  useEffect(() => {
    const t = setInterval(() => {
      if (Date.now() - startedAtRef.current > HARD_TIMEOUT_MS) {
        setTimedOut(true);
      }
    }, 1000);
    return () => clearInterval(t);
  }, []);

  // When job ends, refresh mapping once
  useEffect(() => {
    const status = jobQuery.data?.status;
    if (!status) return;
    if (status === 'completed' || status === 'failed') {
      getZoneNotebookLMStatus(zoneId)
        .then((d) => setMapping(d.notebooklm))
        .catch(() => {
          // ignore: UI can still show job result
        });
    }
  }, [jobQuery.data?.status, zoneId]);

  const derived = useMemo(() => {
    const job = jobQuery.data;
    const progress = computeProgress(job);
    const done = stopPollingFor(job);

    const notebookUrl = job?.notebook_url ?? mapping?.notebookUrl ?? null;

    const stageText = getStageText({ job, isLoading: jobQuery.isLoading, timedOut });

    const rawError = (jobQuery.error as any) || null;
    const messageFromJobOrMapping = job?.error || mapping?.lastError || (mapping as any)?.error || null;
    const errorText = rawError ? getErrorMessage(rawError) : messageFromJobOrMapping;

    const configError = isConfigError(rawError) || (typeof messageFromJobOrMapping === 'string' && messageFromJobOrMapping.includes('FileNotFoundError'));
    const minioLocalhost = hasMinioLocalhostFailure(job);

    return { job, progress, done, notebookUrl, stageText, errorText, configError, minioLocalhost };
  }, [jobQuery.data, jobQuery.isLoading, jobQuery.error, timedOut, mapping?.notebookUrl, mapping?.lastError]);

  if (mapping === null) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="text-base">NotebookLM setup</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground">NotebookLM is not enabled for this zone.</p>
        </CardContent>
      </Card>
    );
  }

  const isReady = derived.job?.status === 'completed' || mapping.status === 'completed';
  const isFailed = derived.job?.status === 'failed' || mapping.status === 'failed';
  const jobResults = derived.job?.results;

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between">
        <CardTitle className="text-base">NotebookLM setup</CardTitle>
        <Badge
          variant={
            isReady ? 'default' : isFailed ? 'destructive' : timedOut ? 'outline' : 'secondary'
          }
        >
          {timedOut ? 'taking too long' : isReady ? 'ready' : isFailed ? 'failed' : 'in progress'}
        </Badge>
      </CardHeader>
      <CardContent className="space-y-4">
        {timedOut && (
          <Alert>
            <TriangleAlert className="h-4 w-4" />
            <AlertTitle>Taking longer than expected</AlertTitle>
            <AlertDescription>
              Import is still running or the gateway is slow. You can keep this page open or retry (owner only).
            </AlertDescription>
          </Alert>
        )}

        {/* Progress */}
        {!isReady && (
          <div className="space-y-2">
            <div className="flex items-center justify-between text-sm">
              <span className="text-muted-foreground">{derived.stageText || 'Імпорт…'}</span>
              <span className={cn('tabular-nums', isFailed && 'text-destructive')}>{derived.progress}%</span>
            </div>
            <Progress value={derived.progress} />
          </div>
        )}

        {/* Error */}
        {isFailed && (
          <Alert variant="destructive">
            <TriangleAlert className="h-4 w-4" />
            <AlertTitle>Імпорт не вдався</AlertTitle>
            <AlertDescription>
              {derived.errorText || 'Сталася невідома помилка.'}

              {derived.minioLocalhost && (
                <div className="mt-3 space-y-2">
                  <p className="text-sm">
                    Схоже, NotebookLM-backend намагається підключитись до MinIO за адресою <span className="font-mono">localhost:9000</span> і не може.
                    Це проблема конфігурації бекенду (повинен бути доступний реальний MinIO endpoint, не localhost).
                  </p>
                  <Button asChild variant="outline" size="sm">
                    <a href="/admin/diagnostics">Перейти до діагностики</a>
                  </Button>
                </div>
              )}

              {Array.isArray(jobResults) && jobResults.length > 0 && (
                <div className="mt-3 space-y-2">
                  <p className="text-sm font-medium">Деталі по джерелах</p>
                  <div className="max-h-40 overflow-auto rounded-md border border-border bg-muted/30 p-2">
                    <ul className="space-y-2">
                      {jobResults.slice(0, 10).map((r, idx) => (
                        <li key={idx} className="text-xs">
                          <div className="flex items-center justify-between gap-2">
                            <span className="truncate font-mono">{formatSourceLabel(r as any)}</span>
                            <span className="tabular-nums text-muted-foreground">{typeof r?.retries === 'number' ? `${r.retries} retries` : ''}</span>
                          </div>
                          {typeof r?.error === 'string' && r.error.trim() && (
                            <div className="mt-1 text-muted-foreground break-words">{r.error}</div>
                          )}
                        </li>
                      ))}
                    </ul>
                    {jobResults.length > 10 && (
                      <p className="mt-2 text-xs text-muted-foreground">Показано 10 з {jobResults.length}.</p>
                    )}
                  </div>
                </div>
              )}

              {derived.configError && (
                <div className="mt-3 space-y-2">
                  <p className="text-sm">
                    Сервіс NotebookLM потребує налаштування адміністратором.
                  </p>
                  <Button asChild variant="outline" size="sm">
                    <a href="/admin/diagnostics">Перейти до діагностики</a>
                  </Button>
                </div>
              )}
            </AlertDescription>
          </Alert>
        )}

        {/* Actions */}
        <div className="flex flex-wrap gap-2">
          {derived.notebookUrl && (
            <Button asChild variant="default" size="sm" className="gap-2">
              <a href={derived.notebookUrl} target="_blank" rel="noreferrer">
                <ExternalLink className="h-4 w-4" />
                Open NotebookLM
              </a>
            </Button>
          )}

          {isOwner && (isFailed || timedOut) && (
            <Button
              type="button"
              variant="outline"
              size="sm"
              className="gap-2"
              onClick={async () => {
                setTimedOut(false);
                setBackoffMs(2500);
                startedAtRef.current = Date.now();
                const resp = await retryNotebookLMImport(zoneId);
                setMapping(resp.notebooklm);
              }}
            >
              <RotateCcw className="h-4 w-4" />
              Retry import
            </Button>
          )}
        </div>

        {/* External service note */}
        <p className="text-xs text-muted-foreground">
          NotebookLM opens in an external Google service in a new tab.
        </p>
      </CardContent>
    </Card>
  );
}
