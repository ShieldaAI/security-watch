import type { Evidence } from './types.js';

/** Source diagnostics safe to display without exposing transport credentials. */
export class SourceError extends Error {}

export class SourceHttpError extends SourceError {
  constructor(
    source: string,
    public readonly status: number,
  ) {
    super(`${source} returned HTTP ${status}.`);
  }
}

export function sourceCanceled(error: unknown): boolean {
  return (
    error instanceof Error &&
    (error.name === 'AbortError' ||
      ('code' in error && ['ABORT_ERR', 'REQUEST_ABORTED'].includes(String(error.code))))
  );
}

export class PartialSourceError extends SourceError {
  constructor(
    message: string,
    public readonly evidence: Evidence[],
  ) {
    super(message);
  }
}

export function throwSourceFailure(error: unknown, evidence: Evidence[]): never {
  if (sourceCanceled(error) || !evidence.length || error instanceof PartialSourceError) throw error;
  const message = error instanceof SourceError ? error.message : 'Source request failed.';
  throw new PartialSourceError(
    `${message} Valid records were retained; collection remains incomplete and its checkpoint was not advanced.`,
    evidence,
  );
}

/** Isolate malformed records without accepting a partially validated record. */
export class SourceItemFailures {
  private count = 0;
  private first: string | undefined;

  read<T>(parse: () => T): T | undefined {
    try {
      return parse();
    } catch (error) {
      if (!(error instanceof SourceError) || error instanceof PartialSourceError) throw error;
      this.count++;
      this.first ??= error.message;
      return undefined;
    }
  }

  message(source: string): string | undefined {
    return this.count
      ? `${source}: ${this.count} invalid item(s) were skipped. ${this.first} Collection remains incomplete and its checkpoint was not advanced.`
      : undefined;
  }

  finish(source: string, evidence: Evidence[]): Evidence[] {
    const message = this.message(source);
    if (message) throw new PartialSourceError(message, evidence);
    return evidence;
  }
}
