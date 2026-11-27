import { useEffect, useMemo, useRef, useState } from 'react';
import { ParsedCsv, parseCsvRows, redactCsvCells } from '../engine/csvParser';
import { redactText } from '../engine/redactor';
import { DetectionOptions, RedactionMode, RedactionResult } from '../types/pii';
import type { SanitizedCsvBundle, WorkerScanRequest, WorkerScanResponse } from '../workers/scanner.worker';

const WORKER_OFFLOAD_CHARS = 8_000;
const WORKER_TIMEOUT_MS = 2_000;

interface ScannerPipelineInput {
  text: string;
  mode: RedactionMode;
  options: DetectionOptions;
  neutralizeFormulas: boolean;
  expectCsv: boolean;
}

/**
 * Coordinates PII scanning and RFC-4180 CSV redaction seamlessly across main RAM (small inputs)
 * and a dedicated Web Worker with stale-request cancellation and a 2s ReDoS termination watchdog.
 */
export function useScannerPipeline({
  text,
  mode,
  options,
  neutralizeFormulas,
  expectCsv,
}: ScannerPipelineInput) {
  const workerRef = useRef<Worker | null>(null);
  const requestIdRef = useRef<number>(0);
  const [workerPayload, setWorkerPayload] = useState<{
    result: RedactionResult;
    originalCsv: ParsedCsv;
    sanitizedCsvBundle: SanitizedCsvBundle;
  } | null>(null);
  const [workerTimeoutError, setWorkerTimeoutError] = useState<string | null>(null);

  const shouldUseWorker =
    typeof Worker !== 'undefined' && (text.length >= WORKER_OFFLOAD_CHARS || options.customRule.enabled);

  useEffect(() => {
    if (!shouldUseWorker) {
      return;
    }

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

    activeWorker.addEventListener('message', handleMessage);

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
    };
  }, [shouldUseWorker, text, mode, options, neutralizeFormulas, expectCsv]);

  useEffect(() => {
    return () => {
      workerRef.current?.terminate();
      workerRef.current = null;
    };
  }, []);

  const result = useMemo(
    () => (shouldUseWorker && workerPayload ? workerPayload.result : redactText(text, mode, options)),
    [shouldUseWorker, workerPayload, text, mode, options],
  );

  const originalCsv = useMemo(
    () => (shouldUseWorker && workerPayload ? workerPayload.originalCsv : parseCsvRows(text, expectCsv)),
    [shouldUseWorker, workerPayload, text, expectCsv],
  );

  const sanitizedCsvBundle = useMemo<SanitizedCsvBundle>(() => {
    if (shouldUseWorker && workerPayload) {
      return workerPayload.sanitizedCsvBundle;
    }
    if (!originalCsv.isTabular) {
      return { headers: [] as string[], rows: [] as string[][], isTabular: false, parseError: null, serializedCsv: '' };
    }
    const { sanitizedHeaders, sanitizedRows, serializedCsv } = redactCsvCells(
      originalCsv,
      mode,
      options,
      neutralizeFormulas,
    );
    return {
      headers: sanitizedHeaders,
      rows: sanitizedRows,
      isTabular: true,
      parseError: null,
      serializedCsv,
    };
  }, [shouldUseWorker, workerPayload, originalCsv, mode, options, neutralizeFormulas]);

  return {
    result,
    originalCsv,
    sanitizedCsvBundle,
    shouldUseWorker,
    workerTimeoutError: shouldUseWorker ? workerTimeoutError : null,
  };
}
