"""
Downloads the NVD JSONL file and parses it into a pandas DataFrame.

NVD data is cached in S3 — downloaded from the source URL at most once per day.
Every 30-minute Lambda invocation pulls from S3 (fast) instead of re-downloading
the full file from the internet.
"""

import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import boto3
import pandas as pd
import requests
from botocore.exceptions import ClientError

from config import (
    NVD_URL,
    NVD_LOCAL_PATH,
    NVD_S3_BUCKET,
    NVD_S3_KEY,
    NVD_CACHE_TTL_SEC,
    START_YEAR,
    DYNAMO_REGION,
)

logger = logging.getLogger(__name__)

_s3_client = None


def _get_s3():
    global _s3_client
    if _s3_client is None:
        _s3_client = boto3.client("s3", region_name=DYNAMO_REGION)
    return _s3_client


# ────────────────────────────────────────────────────────────
# S3 cache helpers
# ────────────────────────────────────────────────────────────

def _s3_cache_is_fresh() -> bool:
    """Check if the S3-cached NVD file exists and is younger than NVD_CACHE_TTL_SEC."""
    try:
        s3 = _get_s3()
        resp = s3.head_object(Bucket=NVD_S3_BUCKET, Key=NVD_S3_KEY)
        last_modified = resp["LastModified"]
        age_sec = (datetime.now(timezone.utc) - last_modified).total_seconds()
        logger.info("S3 NVD cache age: %.0fs (TTL: %ds)", age_sec, NVD_CACHE_TTL_SEC)
        return age_sec < NVD_CACHE_TTL_SEC
    except ClientError as e:
        if e.response["Error"]["Code"] == "404":
            logger.info("No NVD cache in S3 yet")
        else:
            logger.warning("S3 head_object failed: %s", e)
        return False


def _download_from_s3(dest: str = NVD_LOCAL_PATH) -> str:
    """Download NVD file from S3 cache to local disk."""
    logger.info("Downloading NVD from S3 cache: s3://%s/%s", NVD_S3_BUCKET, NVD_S3_KEY)
    t0 = time.time()
    s3 = _get_s3()
    dest_path = Path(dest)
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    s3.download_file(NVD_S3_BUCKET, NVD_S3_KEY, str(dest_path))
    elapsed = time.time() - t0
    size_mb = dest_path.stat().st_size / (1024 * 1024)
    logger.info("Downloaded %.1f MB from S3 in %.1fs", size_mb, elapsed)
    return str(dest_path)


def _upload_to_s3(source: str = NVD_LOCAL_PATH) -> None:
    """Upload the NVD file to S3 cache."""
    logger.info("Uploading NVD to S3 cache: s3://%s/%s", NVD_S3_BUCKET, NVD_S3_KEY)
    t0 = time.time()
    s3 = _get_s3()
    s3.upload_file(source, NVD_S3_BUCKET, NVD_S3_KEY)
    elapsed = time.time() - t0
    logger.info("Uploaded to S3 in %.1fs", elapsed)


def _download_from_url(url: str = NVD_URL, dest: str = NVD_LOCAL_PATH) -> str:
    """Stream-download from the source URL to local disk."""
    logger.info("Downloading NVD from source URL: %s", url)
    t0 = time.time()

    resp = requests.get(url, stream=True, timeout=300)
    resp.raise_for_status()

    dest_path = Path(dest)
    dest_path.parent.mkdir(parents=True, exist_ok=True)

    total_bytes = 0
    with open(dest_path, "wb") as f:
        for chunk in resp.iter_content(chunk_size=1024 * 1024):
            f.write(chunk)
            total_bytes += len(chunk)

    elapsed = time.time() - t0
    size_mb = total_bytes / (1024 * 1024)
    logger.info("Downloaded %.1f MB from URL in %.1fs", size_mb, elapsed)
    return str(dest_path)


# ────────────────────────────────────────────────────────────
# Public API
# ────────────────────────────────────────────────────────────

def download_nvd(url: str = NVD_URL, dest: str = NVD_LOCAL_PATH) -> str:
    """
    Get the NVD data file, using S3 as a daily cache.

    Flow:
      1. Check if S3 has a recent copy (< 24h old)
      2. If yes  → download from S3 (fast, ~5s)
      3. If no   → download from source URL, then upload to S3 for next time

    Returns the local file path.
    """
    if _s3_cache_is_fresh():
        return _download_from_s3(dest)
    else:
        local_path = _download_from_url(url, dest)
        try:
            _upload_to_s3(local_path)
        except Exception as e:
            logger.warning("Failed to upload NVD to S3 cache (non-fatal): %s", e)
        return local_path


def parse_nvd(path: str = NVD_LOCAL_PATH, start_year: int = START_YEAR,
              target_vendors: Optional[set] = None) -> pd.DataFrame:
    """
    Parse the NVD JSON file into a flat DataFrame with columns:
        CVE, Published, vendor, product, version, CVSS

    The file can be either:
      - A JSON array of CVE objects  (single JSON blob)
      - True JSONL (one JSON object per line)

    Only includes entries from start_year onwards.
    If target_vendors is provided, only keeps rows matching those vendors
    (dramatically reduces memory usage).
    """
    logger.info("Parsing NVD data from %s (start_year=%d, vendors=%s) ...",
                path, start_year,
                target_vendors if target_vendors else "ALL")
    t0 = time.time()

    with open(path, "r", encoding="utf-8") as f:
        content = f.read()

    # Auto-detect format
    try:
        data = json.loads(content)
        entries = data if isinstance(data, list) else [data]
    except json.JSONDecodeError:
        entries = [json.loads(line) for line in content.strip().split("\n") if line.strip()]

    # Free the raw string immediately to reduce peak memory
    del content

    rows = []
    for entry in entries:
        cve = entry.get("cve", entry)
        cve_id = cve.get("id", "")
        published = cve.get("published", "")
        if not published:
            continue

        try:
            pub_date = datetime.fromisoformat(published.replace("Z", "+00:00"))
            pub_date = pub_date.replace(tzinfo=None)
        except Exception:
            continue

        if pub_date.year < start_year:
            continue

        # Extract CVSS score (prefer v3.1 > v3.0 > v2)
        metrics = cve.get("metrics", {})
        cvss = None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                cvss = metrics[key][0].get("cvssData", {}).get("baseScore")
                break

        # Extract CPE match entries
        for config in cve.get("configurations", []):
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    if not cpe_match.get("vulnerable"):
                        continue
                    parts = cpe_match.get("criteria", "").split(":")
                    if len(parts) < 5:
                        continue
                    vendor = parts[3]
                    product = parts[4]
                    version = parts[5] if len(parts) > 5 else "*"
                    if not vendor or vendor == "*":
                        continue
                    # Skip vendors we don't care about
                    if target_vendors and vendor not in target_vendors:
                        continue
                    rows.append({
                        "CVE": cve_id,
                        "Published": pub_date,
                        "vendor": vendor,
                        "product": product if product != "*" else None,
                        "version": version if version != "*" else None,
                        "CVSS": cvss,
                        "cpe_criteria": cpe_match.get("criteria", ""),
                    })

    # Free the parsed JSON list to reclaim memory before building DataFrame
    del entries
    if 'data' in dir():
        del data

    df = pd.DataFrame(rows)
    del rows  # free list memory

    if len(df) > 0:
        df["CVSS"] = pd.to_numeric(df["CVSS"], errors="coerce")
        df = df.dropna(subset=["Published", "vendor"])

    elapsed = time.time() - t0
    logger.info("Parsed %d rows (%d unique CVEs) in %.1fs",
                len(df), df["CVE"].nunique() if len(df) > 0 else 0, elapsed)
    return df
