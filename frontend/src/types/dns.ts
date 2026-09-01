/**
 * TypeScript mirror of the JSON produced by `collectors/dns`
 * (see collectors/dns/models.py:DNSCollection.to_dict()).
 *
 * These types intentionally match the Python dataclasses field-for-field
 * so the frontend never has to guess at the collector's output shape.
 * If the collector's schema changes, update this file to match it --
 * do not change the collector to match the frontend.
 */

export type TargetType = "domain" | "hostname" | "ip";

export type CollectionStatus = "success" | "partial" | "failed";

export type QueryStatus =
  | "success"
  | "no_answer"
  | "nxdomain"
  | "timeout"
  | "servfail"
  | "refused"
  | "error";

export interface DnsTarget {
  value: string;
  type: TargetType;
}

export interface CollectorInfo {
  name: string;
  version: string;
}

/** Record-specific fields live in `attributes`; see resolver.py:_normalize_rdata. */
export interface DnsRecordAttributes {
  priority?: number; // MX
  rname?: string; // SOA
  serial?: number; // SOA
  refresh?: number; // SOA
  retry?: number; // SOA
  expire?: number; // SOA
  minimum?: number; // SOA
  flags?: number; // CAA, DNSKEY
  tag?: string; // CAA
  value?: string; // CAA
  protocol?: number; // DNSKEY
  algorithm?: number; // DNSKEY, DS
  key_tag?: number; // DS
  digest_type?: number; // DS
  digest?: string; // DS
  [key: string]: unknown;
}

export interface DnsRecord {
  type: string;
  name: string;
  value: string;
  ttl: number | null;
  attributes: DnsRecordAttributes;
}

/** Entity types the DNS collector currently emits (collector.py). */
export type DnsEntityType = "ip" | "nameserver" | "mail_server" | "hostname";

export interface EntityRelationship {
  entity_type: DnsEntityType | string;
  value: string;
  relationship: string;
  source_record: string;
}

export interface CollectionError {
  query_type: string | null;
  error_type: string;
  message: string;
  resolver: string | null;
}

export interface DnsQueryMetadata {
  query_type: string;
  resolver: string;
  duration_ms: number;
  status: QueryStatus;
}

export interface DnsCollection {
  target: DnsTarget;
  observed_at: string;
  collector: CollectorInfo;
  status: CollectionStatus;
  records: DnsRecord[];
  related_entities: EntityRelationship[];
  queries: DnsQueryMetadata[];
  errors: CollectionError[];
  /** null = not checked (collector's include_dnssec was off); a plain presence check, not full chain validation. */
  dnssec_signed: boolean | null;
}
