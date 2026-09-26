import AdmZip from "adm-zip";
import { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY } from "../config/env.mjs";
import { refreshDynamicL1Cache } from "./globalDomains.mjs";

const TRANCO_ZIP_URL = "https://tranco-list.eu/top-1m.csv.zip";
const BATCH_SIZE = 2000;
const REQUEST_TIMEOUT_MS = 30_000;
const TWENTY_FOUR_HOURS_MS = 24 * 60 * 60 * 1000;

let isSyncing = false;
let syncIntervalTimer = null;

/**
 * Downloads the live Tranco Top-1M list, unzips the CSV in-memory,
 * upserts into Supabase `global_trusted_domains` table, and
 * immediately refreshes the server's in-memory RAM cache.
 */
export async function downloadAndSyncTranco({ limit = null } = {}) {
  if (isSyncing) {
    console.log("[TrancoSync] A sync job is already in progress, skipping.");
    return { skipped: true };
  }

  if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
    console.warn("[TrancoSync] Supabase credentials not found. Sync skipped.");
    return { skipped: true };
  }

  isSyncing = true;
  console.log(
    `[TrancoSync] Starting daily Tranco download from ${TRANCO_ZIP_URL}...`,
  );

  try {
    const response = await fetch(TRANCO_ZIP_URL, {
      signal: AbortSignal.timeout(60_000),
    });
    if (!response.ok)
      throw new Error(`HTTP ${response.status} from Tranco download`);

    const buffer = Buffer.from(await response.arrayBuffer());
    const zip = new AdmZip(buffer);
    const entry = zip.getEntries().find((e) => e.entryName.endsWith(".csv"));
    if (!entry)
      throw new Error("No CSV file found in downloaded Tranco archive.");

    const raw = entry.getData().toString("utf8");
    const lines = raw.split(/\r?\n/).filter(Boolean);
    const rows = [];

    for (const line of lines) {
      const [rankStr, domain] = line.split(",");
      const rank = Number(rankStr);
      if (!domain || !Number.isFinite(rank)) continue;
      rows.push({
        domain: domain.trim().toLowerCase(),
        rank,
        source: "tranco",
      });
      if (limit && rows.length >= limit) break;
    }

    console.log(
      `[TrancoSync] Parsed ${rows.length} domains. Uploading to Supabase in batches of ${BATCH_SIZE}...`,
    );
    let uploaded = 0;
    let failedBatches = 0;

    for (let i = 0; i < rows.length; i += BATCH_SIZE) {
      const batch = rows.slice(i, i + BATCH_SIZE);
      try {
        const res = await fetch(
          `${SUPABASE_URL}/rest/v1/global_trusted_domains?on_conflict=domain`,
          {
            method: "POST",
            headers: {
              apikey: SUPABASE_SERVICE_ROLE_KEY,
              Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
              "content-type": "application/json",
              Prefer: "resolution=merge-duplicates,return=minimal",
            },
            body: JSON.stringify(batch),
            signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
          },
        );

        if (!res.ok) {
          failedBatches += 1;
        } else {
          uploaded += batch.length;
        }
      } catch {
        failedBatches += 1;
      }
    }

    console.log(
      `[TrancoSync] Sync finished: ${uploaded}/${rows.length} uploaded (${failedBatches} batch failures).`,
    );

    // Immediately refresh the in-memory RAM cache with the new top-20K domains
    const cachedCount = await refreshDynamicL1Cache();
    console.log(
      `[TrancoSync] RAM cache refreshed with ${cachedCount} domains.`,
    );

    return { success: true, uploaded, failedBatches };
  } catch (error) {
    console.error("[TrancoSync] Background download failed:", error.message);
    return { success: false, error: error.message };
  } finally {
    isSyncing = false;
  }
}

/**
 * Calculates milliseconds until the next 02:00 AM UTC (off-peak night hour).
 */
function getMsUntilNextTargetTime(targetHourUtc = 2) {
  const now = new Date();
  const nextTarget = new Date(now);
  nextTarget.setUTCHours(targetHourUtc, 0, 0, 0);
  if (nextTarget <= now) {
    nextTarget.setUTCDate(nextTarget.getUTCDate() + 1);
  }
  return nextTarget.getTime() - now.getTime();
}

/**
 * Starts the daily automated sync scheduler in the background.
 * Triggers every night at 02:00 AM UTC without blocking server operations.
 */
export function startDailyTrancoSync() {
  const msUntilFirstRun = getMsUntilNextTargetTime(2);
  const hoursUntil = (msUntilFirstRun / (1000 * 60 * 60)).toFixed(1);
  console.log(
    `[TrancoSync] Next daily sync scheduled in ~${hoursUntil} hours (at 02:00 AM UTC).`,
  );

  // Initial delay until 02:00 AM UTC
  const initialTimeout = setTimeout(() => {
    downloadAndSyncTranco().catch(() => {});

    // Once the first night run completes, repeat every 24 hours
    if (!syncIntervalTimer) {
      syncIntervalTimer = setInterval(() => {
        downloadAndSyncTranco().catch(() => {});
      }, TWENTY_FOUR_HOURS_MS);
      if (syncIntervalTimer.unref) syncIntervalTimer.unref();
    }
  }, msUntilFirstRun);

  if (initialTimeout.unref) initialTimeout.unref();
}
