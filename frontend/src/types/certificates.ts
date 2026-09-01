/**
 * TypeScript mirror of the JSON produced by `collectors/certificates`
 * (see collectors/certificates/models.py:CertificateCollection.to_dict()).
 *
 * Field-for-field compatible with the Python dataclasses, same
 * convention as src/types/dns.ts and src/types/subdomains.ts.
 */

export type CertificateCollectionStatus = "success" | "partial" | "failed";

export type SourceStatus = "success" | "failed";

export type CertificateValidityStatus = "current" | "expired" | "not_yet_valid" | "unknown";

export interface CertificateTarget {
  value: string;
}

export interface CertificateCollectorInfo {
  name: string;
  version: string;
}

export interface SubjectAlternativeName {
  name: string;
  is_wildcard: boolean;
  raw: string;
}

export interface CertificateObservation {
  certificate_id: string;
  common_name: string | null;
  issuer: string | null;
  serial_number: string | null;
  not_before: string | null;
  not_after: string | null;
  sans: SubjectAlternativeName[];
  fingerprint_sha256: string | null;
  signature_algorithm: string | null;
  public_key_algorithm: string | null;
  status: CertificateValidityStatus;
  source: string;
  method: string;
  source_reference: string | null;
  observed_at: string;
  has_wildcard_san: boolean;
}

export interface CertificateSourceResult {
  source: string;
  status: SourceStatus;
  candidate_count: number;
  error_type: string | null;
  message: string | null;
}

export interface CertificateEntityRelationship {
  entity_type: string;
  value: string;
  relationship: string;
  source_record: string;
}

export interface CertificateCollectionError {
  query_type: string | null;
  error_type: string;
  message: string;
}

export interface CertificateCollection {
  target: CertificateTarget;
  observed_at: string;
  collector: CertificateCollectorInfo;
  status: CertificateCollectionStatus;
  certificates: CertificateObservation[];
  related_entities: CertificateEntityRelationship[];
  sources: CertificateSourceResult[];
  errors: CertificateCollectionError[];
  candidate_count: number;
  truncated: boolean;
}
