import { isTopGlobalDomain } from "@trustlens/domain";
import { SUPABASE_SERVICE_ROLE_KEY, SUPABASE_URL } from "../config/env.mjs";

const LOOKUP_TIMEOUT_MS = 3_000;
const REFRESH_TIMEOUT_MS = 15_000;
const TWENTY_FOUR_HOURS_MS = 24 * 60 * 60 * 1000;

// In-memory dynamic RAM cache for Tier 3 L1 (Top ~20,000 domains)
const dynamicL1Cache = new Set();
let refreshTimer = null;

/**
 * Fetches the latest top 20,000 domains from Supabase L2 into server RAM.
 * Fetches in parallel chunks of 1,000 (Supabase PostgREST default limit).
 * Non-blocking and fail-safe: if Supabase fails or is empty, the static
 * @trustlens/domain fallback is still active.
 */
export async function refreshDynamicL1Cache() {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) return 0;

  try {
    const CHUNK_SIZE = 1000;
    const TOTAL_CHUNKS = 20; // 20 x 1000 = 20,000 domains

    const chunkPromises = Array.from({ length: TOTAL_CHUNKS }, async (_, i) => {
      const offset = i * CHUNK_SIZE;
      const params = new URLSearchParams({
        select: "domain",
        order: "rank.asc",
        limit: String(CHUNK_SIZE),
        offset: String(offset),
      });

      const response = await fetch(
        `${SUPABASE_URL}/rest/v1/global_trusted_domains?${params}`,
        {
          headers: {
            apikey: SUPABASE_SERVICE_ROLE_KEY,
            Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
          },
          signal: AbortSignal.timeout(REFRESH_TIMEOUT_MS),
        },
      );

      if (!response.ok) return [];
      const rows = await response.json();
      return Array.isArray(rows) ? rows.map((r) => r.domain) : [];
    });

    const results = await Promise.all(chunkPromises);
    const allDomains = results.flat();

    if (allDomains.length >= 100) {
      dynamicL1Cache.clear();
      for (const d of allDomains) {
        dynamicL1Cache.add(d.toLowerCase());
      }
      return dynamicL1Cache.size;
    }
  } catch (err) {
    // Fail-open: network error shouldn't crash the server or invalidate existing cache
    console.warn(
      "[GlobalDomains] Background RAM cache refresh skipped:",
      err.message,
    );
  }

  return dynamicL1Cache.size;
}

/**
 * Starts the automatic 24-hour background refresh cycle.
 */
export function startGlobalDomainsAutoRefresh() {
  // Trigger initial background refresh
  refreshDynamicL1Cache().catch(() => {});

  if (!refreshTimer) {
    refreshTimer = setInterval(() => {
      refreshDynamicL1Cache().catch(() => {});
    }, TWENTY_FOUR_HOURS_MS);

    // Allow Node.js to exit cleanly in unit tests
    if (refreshTimer.unref) refreshTimer.unref();
  }
}

async function isInL2GlobalDomains(domain) {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) return false;
  const params = new URLSearchParams({
    domain: `eq.${domain}`,
    select: "domain",
    limit: "1",
  });
  const response = await fetch(
    `${SUPABASE_URL}/rest/v1/global_trusted_domains?${params}`,
    {
      headers: {
        apikey: SUPABASE_SERVICE_ROLE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
      },
      signal: AbortSignal.timeout(LOOKUP_TIMEOUT_MS),
    },
  );
  if (!response.ok) throw new Error("Global domain L2 lookup failed");
  const rows = await response.json();
  return rows.length > 0;
}

function buildFinding(domain, tier) {
  return {
    canonicalSignal: "known_global_domain",
    category: "Domain verification",
    evidence: `${domain} is a globally recognized, high-traffic domain.`,
    cacheTier: tier,
    source: "DOMAIN_DIRECTORY",
    strength: 0.5,
    confidence: 0.8,
    limitation:
      "Global popularity is supporting evidence only; it does not confirm this specific message is legitimate, and does not rule out impersonation elsewhere in the same message.",
    detectorVersion: "global-domains-v1",
  };
}

/**
 * Tier 3 of the domain verification pipeline:
 * 1. Checks dynamic RAM cache (dynamicL1Cache)
 * 2. Checks bundled static top-20K (isTopGlobalDomain)
 * 3. Falls through to Supabase L2 database (full 1M)
 */
export async function checkGlobalDomainTrust(entities) {
  const domainEntity = entities.find((entity) => entity.type === "domain");
  if (!domainEntity) return { findings: [] };
  const domain = (
    domainEntity.normalizedValue ||
    domainEntity.value ||
    ""
  ).toLowerCase();
  if (!domain) return { findings: [] };

  // L1 Check: Dynamic RAM cache OR static top-20k fallback
  if (dynamicL1Cache.has(domain) || isTopGlobalDomain(domain)) {
    return { findings: [buildFinding(domain, "L1")] };
  }

  // L2 Check: Supabase database query (top 1M)
  try {
    const foundInL2 = await isInL2GlobalDomains(domain);
    if (foundInL2) return { findings: [buildFinding(domain, "L2")] };
  } catch {
    // Supplementary evidence; failed L2 lookup never blocks analysis
  }

  return { findings: [] };
}
