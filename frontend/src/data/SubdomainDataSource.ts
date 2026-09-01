import type { SubdomainCollection } from "../types/subdomains";

/**
 * Separate from InvestigationDataSource (which is typed for DnsCollection)
 * rather than a shared generic interface -- the subdomain collector is a
 * genuinely independent collector with its own schema and its own
 * endpoint, and forcing both through one interface would be exactly the
 * cross-collector coupling the platform's architecture avoids.
 */
export interface SubdomainDataSource {
  load(target: string): Promise<SubdomainCollection>;
}

export class SubdomainApiDataSource implements SubdomainDataSource {
  constructor(private readonly baseUrl: string) {}

  async load(target: string): Promise<SubdomainCollection> {
    let response: Response;

    try {
      // enable_bruteforce=true turns on the active DNS wordlist source
      // (see collectors/subdomains/sources/dns_bruteforce.py) alongside
      // the default Certificate Transparency source -- without it, this
      // request only ever exercises crt.sh, which leaves the panel empty
      // whenever crt.sh itself is unavailable.
      response = await fetch(
        `${this.baseUrl}/investigations/subdomains/${encodeURIComponent(target)}?enable_bruteforce=true`
      );
    } catch {
      throw new Error(`Could not reach the investigation service at ${this.baseUrl}. Is the backend running?`);
    }

    if (!response.ok) {
      throw new Error(await describeHttpError(response, target));
    }

    return (await response.json()) as SubdomainCollection;
  }
}

async function describeHttpError(response: Response, target: string): Promise<string> {
  try {
    const body = (await response.json()) as { detail?: unknown };
    if (typeof body.detail === "string") return body.detail;
  } catch {
    // Response body wasn't JSON -- fall through to the generic message.
  }

  return `Failed to load subdomain investigation for ${target}: HTTP ${response.status}`;
}
