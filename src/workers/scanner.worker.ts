import { executeSanitizationPipeline, PipelineInput, PipelineOutput } from '../engine/pipeline';

export type { SanitizedCsvBundle } from '../engine/pipeline';

export interface WorkerScanRequest extends PipelineInput {
  requestId: number;
}

export interface WorkerScanResponse extends PipelineOutput {
  requestId: number;
}

globalThis.addEventListener('message', (event: MessageEvent<WorkerScanRequest>) => {
  const { requestId, ...pipelineInput } = event.data;
  const output = executeSanitizationPipeline(pipelineInput);
  const response: WorkerScanResponse = { requestId, ...output };
  globalThis.postMessage(response);
});
