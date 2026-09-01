import type { CertificateCollection } from "../types/certificates";

/**
 * Separate from InvestigationDataSource/SubdomainDataSource (each typed
 * for its own collection) rather than a shared generic interface -- the
 * certificate collector is a genuinely independent collector with its own
 * schema and its own endpoint, matching the same reasoning
 * SubdomainDataSource.ts documents for keeping these interfaces apart.
 */
export interface CertificateDataSource {
  load(target: string): Promise<CertificateCollection>;
}

export class CertificateApiDataSource implements CertificateDataSource {
  constructor(private readonly baseUrl: string) {}

  async load(target: string): Promise<CertificateCollection> {
    let response: Response;

    try {
      response = await fetch(`${this.baseUrl}/investigations/certificates/${encodeURIComponent(target)}`);
    } catch {
      throw new Error(`Could not reach the investigation service at ${this.baseUrl}. Is the backend running?`);
    }

    if (!response.ok) {
      throw new Error(await describeHttpError(response, target));
    }

    return (await response.json()) as CertificateCollection;
  }
}

async function describeHttpError(response: Response, target: string): Promise<string> {
  try {
    const body = (await response.json()) as { detail?: unknown };
    if (typeof body.detail === "string") return body.detail;
  } catch {
    // Response body wasn't JSON -- fall through to the generic message.
  }

  return `Failed to load certificate investigation for ${target}: HTTP ${response.status}`;
}
