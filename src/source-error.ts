import type { Evidence } from './types.js';

/** Source diagnostics safe to display without exposing transport credentials. */
export class SourceError extends Error {}

export class PartialSourceError extends SourceError {
  constructor(
    message: string,
    public readonly evidence: Evidence[],
  ) {
    super(message);
  }
}
