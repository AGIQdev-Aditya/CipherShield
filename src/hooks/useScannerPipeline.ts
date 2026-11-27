import { useEffect, useMemo, useRef, useState } from 'react';
import { executeSanitizationPipeline, PipelineInput, PipelineOutput } from '../engine/pipeline';
import type { WorkerScanRequest, WorkerScanResponse } from '../workers/scanner.worker';

const WORKER_OFFLOAD_CHARS = 8_000;
const WORKER_TIMEOUT_MS = 2_000;

/**
 * Coordinates PII scanning and RFC-4180 CSV redaction seamlessly across main RAM (small inputs)
 * and a dedicated Web Worker with stale-request cancellation and a 2s ReDoS termination watchdog.
 */
export function useScannerPipeline(input: PipelineInput) {
  const { text, mode, options, neutralizeFormulas, expectCsv } = input;
  const workerRef = useRef<Worker | null>(null);
  const requestIdRef = useRef<number>(0);
  const [workerPayload, setWorkerPayload] = useState<PipelineOutput | null>(null);
  const [workerTimeoutError, setWorkerTimeoutError] = useState<string | null>(null);

  const shouldUseWorker =
    typeof Worker !== 'undefined' && (text.length >= WORKER_OFFLOAD_CHARS || options.customRule.enabled);

  useEffect(() => {
    if (!shouldUseWorker) return;

    if (!workerRef.current) {
      workerRef.current = new Worker(new URL('../workers/scanner.worker.ts', import.meta.url), {
        type: 'module',
      });
    }

    const activeWorker = workerRef.current;
    const reqId = requestIdRef.current + 1;
    requestIdRef.current = reqId;

    const handleMessage = (event: MessageEvent<WorkerScanResponse>) => {
      if (event.data.requestId !== requestIdRef.current) return;
      window.clearTimeout(watchdog);
      setWorkerTimeoutError(null);
      setWorkerPayload({
        result: event.data.result,
        originalCsv: event.data.originalCsv,
        sanitizedCsvBundle: event.data.sanitizedCsvBundle,
      });
    };

    const handleError = () => {
      if (requestIdRef.current !== reqId) return;
      window.clearTimeout(watchdog);
      setWorkerTimeoutError('Isolated Web Worker scan encountered an execution error.');
    };

    activeWorker.addEventListener('message', handleMessage);
    activeWorker.addEventListener('error', handleError);

    const watchdog = window.setTimeout(() => {
      if (requestIdRef.current === reqId) {
        activeWorker.terminate();
        workerRef.current = null;
        setWorkerTimeoutError('Scan aborted after 2000ms inside isolated Web Worker (ReDoS protection).');
      }
    }, WORKER_TIMEOUT_MS);

    const payload: WorkerScanRequest = {
      requestId: reqId,
      text,
      mode,
      options,
      neutralizeFormulas,
      expectCsv,
    };
    activeWorker.postMessage(payload);

    return () => {
      window.clearTimeout(watchdog);
      activeWorker.removeEventListener('message', handleMessage);
      activeWorker.removeEventListener('error', handleError);
    };
  }, [shouldUseWorker, text, mode, options, neutralizeFormulas, expectCsv]);

  useEffect(() => {
    return () => {
      workerRef.current?.terminate();
      workerRef.current = null;
    };
  }, []);

  const syncOutput = useMemo(
    () =>
      shouldUseWorker && workerPayload
        ? workerPayload
        : executeSanitizationPipeline({ text, mode, options, neutralizeFormulas, expectCsv }),
    [shouldUseWorker, workerPayload, text, mode, options, neutralizeFormulas, expectCsv],
  );

  return {
    ...syncOutput,
    shouldUseWorker,
    workerTimeoutError: shouldUseWorker ? workerTimeoutError : null,
  };
}
