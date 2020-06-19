import { AuditResults } from './types';

// eslint-disable-next-line @typescript-eslint/no-empty-interface
export interface Options {
  //
}

// eslint-disable-next-line @typescript-eslint/no-empty-interface
export interface AuditReport {
  //
}

export const generateReport = (
  options: Options,
  results: AuditResults
): AuditReport => {
  return {};
};
