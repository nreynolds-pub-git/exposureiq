/**
 * Anonymize Tenable One connector source codes to generic industry categories.
 *
 * Mirrors backend/src/t1_cve_enricher/enrichment/source_category.py.
 * Keep the two in sync when adding new connectors.
 *
 * Why this exists: the Explain feature sends finding context to a user-chosen
 * LLM provider via BYOK. Customers are sometimes commercially sensitive about
 * disclosing which specific security vendors they use; this module ensures no
 * vendor identity reaches the LLM.
 *
 * Unknown source codes fall back to a generic label rather than passing
 * through the raw code — this is the privacy invariant.
 */

const SOURCE_CATEGORIES: Record<string, string> = {
  // EDR / endpoint
  'JAMF:EDR': 'EDR',
  'MICROSOFT:TVM': 'EDR',
  'SENTINEL-ONE:EDR': 'EDR',
  // CNAPP / cloud security
  'ORCA:CSPM': 'CNAPP',
  'PALO-ALTO-NETWORKS:CSPM': 'CNAPP',
  'PRISMA-CLOUD:CSPM': 'CNAPP',
  'WIZ:CONFIGURATION': 'CNAPP',
  'WIZ:ISSUES': 'CNAPP',
  'WIZ:VM': 'CNAPP',
  // DAST / web application scanning
  'INVICTI:WHITEHAT-DAST': 'DAST',
  'MASTERCARD:DAST': 'DAST',
  // EASM / external attack surface (note: Tenable codes Cycognito as :DAST
  // but the tool is functionally EASM)
  'CY-COGNITO:DAST': 'EASM',
  // Third-party risk rating
  'RISK-RECON:RR': 'Third-party risk rating',
  'SECURITY-SCORECARD:DAST': 'Third-party risk rating',
  // Other
  'AWS:AINV': 'Cloud inventory',
  'RED-HAT:VM': 'OS vulnerability scanner',
  'SERVICE-NOW:AINV': 'CMDB',
  'SNYK:SNYK': 'SCA',
};

const FALLBACK = 'Third-party security tool';

export function categoryFor(sourceCode: string | null | undefined): string {
  if (!sourceCode) return FALLBACK;
  return SOURCE_CATEGORIES[sourceCode] ?? FALLBACK;
}
