/**
 * TypeScript mirror of the JSON produced by `collectors/subdomains`
 * (see collectors/subdomains/models.py:SubdomainCollection.to_dict()).
 *
 * Field-for-field compatible with the Python dataclasses, same
 * convention as src/types/dns.ts.
 */

export type SubdomainCollectionStatus = "success" | "partial" | "failed";

export type SourceStatus = "success" | "failed";

export type DnsValidationStatus = "not_checked" | "resolved" | "unresolved";

export interface SubdomainTarget {
  value: string;
}

export interface SubdomainCollectorInfo {
  name: string;
  version: string;
}

export interface DiscoveryEvidence {
  source: string;
  method: string;
  observed_at: string;
  source_reference: string | null;
}

export interface ResolvedRecord {
  type: string;
  value: string;
  ttl: number | null;
}

export interface SubdomainObservation {
  hostname: string;
  parent_domain: string;
  discovery: DiscoveryEvidence[];
  dns_status: DnsValidationStatus;
  dns_records: ResolvedRecord[];
  is_wildcard_match: boolean;
}

export interface SourceResult {
  source: string;
  status: SourceStatus;
  candidate_count: number;
  error_type: string | null;
  message: string | null;
}

export interface SubdomainEntityRelationship {
  entity_type: string;
  value: string;
  relationship: string;
  source_record: string;
}

export interface SubdomainCollectionError {
  query_type: string | null;
  error_type: string;
  message: string;
}

export interface SubdomainCollection {
  target: SubdomainTarget;
  observed_at: string;
  collector: SubdomainCollectorInfo;
  status: SubdomainCollectionStatus;
  observations: SubdomainObservation[];
  related_entities: SubdomainEntityRelationship[];
  sources: SourceResult[];
  errors: SubdomainCollectionError[];
  candidate_count: number;
  truncated: boolean;
}
