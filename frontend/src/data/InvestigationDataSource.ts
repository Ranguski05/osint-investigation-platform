import type { DnsCollection } from "../types/dns";

/**
 * Abstraction over "how do we get a DNS collection for a target".
 *
 * The graph and panels only depend on this interface, never on `fetch`
 * or file paths directly. That is what lets us swap the static JSON
 * file for a live FastAPI endpoint later without touching any
 * visualization code -- only `ApiDataSource` needs to be written and
 * wired up in place of `FileDataSource`.
 */
export interface InvestigationDataSource {
  load(target: string): Promise<DnsCollection>;
}

/**
 * Loads a previously-saved collector JSON file from `frontend/public`.
 *
 * This is the "phase 1" data source: the output of
 *   python -m collectors.dns example.com --json
 * saved to a file and dropped into `public/`.
 */
export class FileDataSource implements InvestigationDataSource {
  constructor(private readonly fileName: string) {}

  async load(_target: string): Promise<DnsCollection> {
    const response = await fetch(`/${this.fileName}`);

    if (!response.ok) {
      throw new Error(
        `Failed to load ${this.fileName}: HTTP ${response.status}`
      );
    }

    const data = (await response.json()) as unknown;

    return validateDnsCollection(data);
  }
}

/**
 * Future data source: fetches a live collection from the FastAPI backend.
 *
 * Left unused for now (see FUTURE API in the project brief) but included
 * so the intended swap is concrete rather than hypothetical:
 *
 *   const source: InvestigationDataSource = import.meta.env.PROD
 *     ? new ApiDataSource("/api")
 *     : new FileDataSource("example-dns.json");
 */
export class ApiDataSource implements InvestigationDataSource {
  constructor(private readonly baseUrl: string) {}

  async load(target: string): Promise<DnsCollection> {
    let response: Response;

    try {
      response = await fetch(
        `${this.baseUrl}/investigations/dns/${encodeURIComponent(target)}`
      );
    } catch {
      // fetch() itself throws (not an HTTP error response) when the
      // backend isn't reachable at all -- distinguish that from a bad
      // request/response so the UI can show a useful message.
      throw new Error(
        `Could not reach the investigation service at ${this.baseUrl}. Is the backend running?`
      );
    }

    if (!response.ok) {
      throw new Error(await describeHttpError(response, target));
    }

    const data = (await response.json()) as unknown;

    return validateDnsCollection(data);
  }
}

async function describeHttpError(response: Response, target: string): Promise<string> {
  try {
    const body = (await response.json()) as { detail?: unknown };
    if (typeof body.detail === "string") return body.detail;
  } catch {
    // Response body wasn't JSON -- fall through to the generic message.
  }

  return `Failed to load investigation for ${target}: HTTP ${response.status}`;
}

/**
 * Minimal structural validation.
 *
 * This is not a full schema validator -- it exists to fail loudly with a
 * useful message if the JSON is malformed or from an incompatible
 * collector version, rather than letting `undefined` silently propagate
 * into the graph and panels.
 */
function validateDnsCollection(data: unknown): DnsCollection {
  if (typeof data !== "object" || data === null) {
    throw new Error("Investigation data is not a JSON object.");
  }

  const candidate = data as Record<string, unknown>;

  const requiredFields = [
    "target",
    "observed_at",
    "collector",
    "status",
    "records",
    "related_entities",
    "queries",
    "errors",
  ];

  const missing = requiredFields.filter((field) => !(field in candidate));

  if (missing.length > 0) {
    throw new Error(
      `Investigation data is missing required field(s): ${missing.join(", ")}`
    );
  }

  return candidate as unknown as DnsCollection;
}
