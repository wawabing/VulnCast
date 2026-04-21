"""
Downloads the NVD data file, using S3 as a daily cache.
Shared logic with the CPE forecast service.
"""

import logging
import time
from datetime import datetime, timezone
from pathlib import Path

import boto3
import requests
from botocore.exceptions import ClientError

from config import NVD_URL, NVD_LOCAL_PATH, NVD_S3_BUCKET, NVD_S3_KEY, NVD_CACHE_TTL_SEC, DYNAMO_REGION

logger = logging.getLogger(__name__)

_s3_client = None


def _get_s3():
    global _s3_client
    if _s3_client is None:
        _s3_client = boto3.client("s3", region_name=DYNAMO_REGION)
    return _s3_client


def _s3_cache_is_fresh() -> bool:
    try:
        resp = _get_s3().head_object(Bucket=NVD_S3_BUCKET, Key=NVD_S3_KEY)
        age_sec = (datetime.now(timezone.utc) - resp["LastModified"]).total_seconds()
        logger.info("S3 NVD cache age: %.0fs (TTL: %ds)", age_sec, NVD_CACHE_TTL_SEC)
        return age_sec < NVD_CACHE_TTL_SEC
    except ClientError as e:
        if e.response["Error"]["Code"] == "404":
            logger.info("No NVD cache in S3 yet")
        else:
            logger.warning("S3 head_object failed: %s", e)
        return False


def _download_from_s3(dest: str = NVD_LOCAL_PATH) -> str:
    logger.info("Downloading NVD from S3 cache ...")
    t0 = time.time()
    dest_path = Path(dest)
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    _get_s3().download_file(NVD_S3_BUCKET, NVD_S3_KEY, str(dest_path))
    size_mb = dest_path.stat().st_size / (1024 * 1024)
    logger.info("Downloaded %.1f MB from S3 in %.1fs", size_mb, time.time() - t0)
    return str(dest_path)


def _download_from_url(url: str = NVD_URL, dest: str = NVD_LOCAL_PATH) -> str:
    logger.info("Downloading NVD from source URL: %s", url)
    t0 = time.time()
    resp = requests.get(url, stream=True, timeout=600)
    resp.raise_for_status()
    dest_path = Path(dest)
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    total_bytes = 0
    with open(dest_path, "wb") as f:
        for chunk in resp.iter_content(chunk_size=1024 * 1024):
            f.write(chunk)
            total_bytes += len(chunk)
    logger.info("Downloaded %.1f MB from URL in %.1fs", total_bytes / (1024 * 1024), time.time() - t0)
    return str(dest_path)


def _upload_to_s3(source: str = NVD_LOCAL_PATH) -> None:
    logger.info("Uploading NVD to S3 cache ...")
    t0 = time.time()
    _get_s3().upload_file(source, NVD_S3_BUCKET, NVD_S3_KEY)
    logger.info("Uploaded to S3 in %.1fs", time.time() - t0)


def download_nvd() -> str:
    if _s3_cache_is_fresh():
        return _download_from_s3()
    else:
        local_path = _download_from_url()
        try:
            _upload_to_s3(local_path)
        except Exception as e:
            logger.warning("Failed to upload NVD to S3 cache: %s", e)
        return local_path
