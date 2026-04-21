import csv
import re
import time
from datetime import datetime, date
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

BASE = "https://endoflife.date/api/v1"
INPUT_FILE = r"C:\Users\owenw\Desktop\DISSER ITEMS\intune_raw_test.csv"
OUTPUT_FILE = r"C:\Users\owenw\Desktop\DISSER ITEMS\intune_eol_output.csv"

# ── Resilient HTTP session (reuses connections & retries) ──────
session = requests.Session()
retries = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503])
session.mount("https://", HTTPAdapter(max_retries=retries))
session.headers.update({"Accept": "application/json"})

# ── Caches ──────────────────────────────────────────────────────
product_catalog = []        # full product list from API
release_cache   = {}        # product_slug -> releases list
match_cache     = {}        # raw input string -> product_slug | None
tag_products    = {}        # tag -> [product dicts] (lazy-loaded from catalog)
latest_cache    = {}        # product_slug -> latest non-EOL release label


# ── Fetch product catalog ──────────────────────────────────────
def fetch_product_catalog():
    """Load every product (name, label, aliases, tags) from endoflife.date."""
    global product_catalog
    resp = session.get(f"{BASE}/products/")
    resp.raise_for_status()
    product_catalog = resp.json()["result"]
    # Build tag → product index from catalog (no extra API calls)
    for p in product_catalog:
        for t in p.get("tags", []):
            tag_products.setdefault(t, []).append(p)
    print(f"Loaded {len(product_catalog)} products from endoflife.date")


# ── Normalise helper ───────────────────────────────────────────
def normalize(text):
    return re.sub(r"[^a-z0-9\s]", "", text.lower()).strip()


# ── Dynamic product matcher ───────────────────────────────────
def find_product(input_string):
    """
    Find the best-matching endoflife.date product slug for an arbitrary
    name string (OS description, application name, etc.).
    """
    if not input_string:
        return None
    if input_string in match_cache:
        return match_cache[input_string]

    norm_input = normalize(input_string)
    best_match = None
    best_score = 0.0

    for product in product_catalog:
        candidates = [product["label"], product["name"]] + product.get("aliases", [])

        for candidate in candidates:
            norm_cand = normalize(candidate)
            if not norm_cand:
                continue

            if norm_cand == norm_input:
                match_cache[input_string] = product["name"]
                return product["name"]

            if len(norm_cand) >= 3 and norm_cand in norm_input:
                if re.search(r"\b" + re.escape(norm_cand) + r"\b", norm_input):
                    score = len(norm_cand) / max(len(norm_input), 1) + 0.2
                    if score > best_score:
                        best_score = score
                        best_match = product["name"]

            if len(norm_input) >= 3 and norm_input in norm_cand:
                if re.search(r"\b" + re.escape(norm_input) + r"\b", norm_cand):
                    score = len(norm_input) / max(len(norm_cand), 1) + 0.2
                    if score > best_score:
                        best_score = score
                        best_match = product["name"]

    if best_score >= 0.45:
        match_cache[input_string] = best_match
        return best_match

    match_cache[input_string] = None
    return None


def _product_label(slug):
    """Return human-friendly label for a product slug."""
    for p in product_catalog:
        if p["name"] == slug:
            return p["label"]
    return slug


def _product_tags(slug):
    """Return the tag list for a product slug."""
    for p in product_catalog:
        if p["name"] == slug:
            return p.get("tags", [])
    return []


# ── Fetch releases ─────────────────────────────────────────────
def get_releases(product_slug):
    if product_slug in release_cache:
        return release_cache[product_slug]
    try:
        resp = session.get(f"{BASE}/products/{product_slug}")
        if resp.status_code != 200:
            release_cache[product_slug] = []
            return []
        releases = resp.json()["result"]["releases"]
        release_cache[product_slug] = releases
        return releases
    except requests.RequestException as e:
        print(f"  [WARN] Failed to fetch releases for {product_slug}: {e}")
        release_cache[product_slug] = []
        return []


# ── Version → release matcher ─────────────────────────────────
def match_release(product_slug, version_string, description=""):
    """
    Walk the releases list for *product_slug* and return the best
    matching release dict, or None.
    """
    releases = get_releases(product_slug)
    if not releases:
        return None

    # ── Windows-specific: pick edition (-e / -w) by description ──
    if product_slug == "windows":
        is_enterprise = any(
            kw in description for kw in ("Enterprise", "Education")
        )
        suffix = "-e" if is_enterprise else "-w"

        matches = [
            r for r in releases
            if (r.get("latest") or {}).get("name", "") == version_string
        ]
        edition = [r for r in matches if r["name"].endswith(suffix)]
        if edition:
            return edition[0]
        if matches:
            return matches[0]

        for r in releases:
            ln = (r.get("latest") or {}).get("name", "")
            if ln and version_string.startswith(ln):
                if r["name"].endswith(suffix):
                    return r
        for r in releases:
            ln = (r.get("latest") or {}).get("name", "")
            if ln and version_string.startswith(ln):
                return r
        return None

    # ── Generic matching for every other product ──
    for r in releases:
        latest_name = (r.get("latest") or {}).get("name", "")
        if version_string == r.get("name", "") or version_string == latest_name:
            return r

    for r in releases:
        cycle = r.get("name", "")
        if cycle and (
            version_string.startswith(cycle + ".")
            or version_string.startswith(cycle + "-")
        ):
            return r

    major = version_string.split(".")[0] if version_string else ""
    if major:
        for r in releases:
            if r.get("name", "") == major:
                return r

    return None


# ── Find best non-EOL release for a product ───────────────────
def get_recommended_release(product_slug, description=""):
    """
    Return the newest actively-maintained, non-EOL release for a product.
    For Windows, respects the edition suffix from the description.
    """
    releases = get_releases(product_slug)
    if not releases:
        return None

    if product_slug == "windows":
        is_enterprise = any(
            kw in description for kw in ("Enterprise", "Education")
        )
        suffix = "-e" if is_enterprise else "-w"
        # Prefer maintained + correct edition
        for r in releases:
            if not r.get("isEol") and r["name"].endswith(suffix):
                return r
        # Fallback: any non-EOL
        for r in releases:
            if not r.get("isEol"):
                return r
        return None

    # Generic: first non-EOL release (list is newest-first from API)
    for r in releases:
        if not r.get("isEol"):
            return r
    return None


def _format_release_rec(product_slug, release):
    """Format a release recommendation as a readable string."""
    if not release:
        return ""
    label = _product_label(product_slug)
    ver = release.get("label", release.get("name", ""))
    latest_ver = (release.get("latest") or {}).get("name", "")
    eol_from = release.get("eolFrom", "")

    parts = [f"{label} {ver}"]
    if latest_ver:
        parts[0] += f" (build {latest_ver})"
    if eol_from:
        parts.append(f"EOL: {eol_from}")
    else:
        parts.append("no EOL date set")
    return " | ".join(parts)


# ── Find alternative products via shared tags ──────────────────
def get_alternatives(product_slug, max_alternatives=3):
    """
    Find other products that share *specific* tags with *product_slug*
    and belong to the same category. Returns their latest non-EOL release.
    """
    # Tags that are too broad to be useful for finding alternatives
    BROAD_TAGS = {
        "app", "os", "framework", "lang", "server-app", "service",
        "database", "device", "standard",
        # Vendor tags are too broad — "microsoft" returns 20+ unrelated products
        "microsoft", "google", "amazon", "alibaba", "apple", "red-hat",
        "oracle", "ibm", "cisco", "adobe", "meta", "intel", "nvidia",
        "atlassian", "elastic", "hashicorp", "jetbrains", "sap",
        "vmware", "hpe", "fortinet", "citrix", "gitlab", "herodevs",
        "bellsoft", "azul", "eclipse", "cncf", "linux-foundation",
        "progress", "sonarsource", "sony", "suse", "veeam", "veritas",
        "vercel", "zerto", "mondoo", "netapp", "stormshield",
        "mikrotik", "nutanix", "palo-alto-networks", "mozilla",
        "influxdata", "meilisearch", "motorola", "rust-foundation",
    }

    # Get the category of the current product for filtering
    product_category = ""
    tags = []
    for p in product_catalog:
        if p["name"] == product_slug:
            tags = p.get("tags", [])
            product_category = p.get("category", "")
            break

    # Only use specific / functional tags (e.g. "web-browser", "linux-distribution")
    specific_tags = [t for t in tags if t not in BROAD_TAGS]

    if not specific_tags:
        return []

    seen = {product_slug}
    alternatives = []

    for tag in specific_tags:
        for p in tag_products.get(tag, []):
            slug = p["name"]
            if slug in seen:
                continue
            # Must be the same category (os→os, app→app, etc.)
            if product_category and p.get("category") != product_category:
                continue
            seen.add(slug)

            rec = get_recommended_release(slug)
            if not rec:
                continue
            alternatives.append({
                "product": slug,
                "label": p["label"],
                "release": rec.get("label", rec.get("name", "")),
                "latest_build": (rec.get("latest") or {}).get("name", ""),
                "eol_date": rec.get("eolFrom", ""),
            })
            if len(alternatives) >= max_alternatives:
                return alternatives

    return alternatives


def _format_alternatives(alts):
    """Format a list of alternative products as a semicolon-separated string."""
    parts = []
    for a in alts:
        entry = f"{a['label']} {a['release']}"
        if a["latest_build"]:
            entry += f" (build {a['latest_build']})"
        if a["eol_date"]:
            entry += f" EOL:{a['eol_date']}"
        parts.append(entry)
    return "; ".join(parts)


# ── Days until EOL ─────────────────────────────────────────────
def days_until_eol(eol_date_str):
    """Return days until EOL, negative if already past, or '' if unknown."""
    if not eol_date_str:
        return ""
    try:
        eol_date = datetime.strptime(str(eol_date_str), "%Y-%m-%d").date()
        return (eol_date - date.today()).days
    except (ValueError, TypeError):
        return ""


# ── Build EOL + recommendation result ─────────────────────────
def eol_result(product_slug, version, description=""):
    empty = {
        "product": "", "release": "", "eol_date": "", "is_eol": "",
        "days_to_eol": "", "recommended": "", "alternatives": "",
    }
    if not product_slug:
        return empty

    release = match_release(product_slug, version, description)
    if not release:
        return {
            **empty,
            "product": product_slug,
            "release": "no match",
        }

    is_eol = release.get("isEol", "")
    eol_from = release.get("eolFrom", "")
    d_to_eol = days_until_eol(eol_from)

    # Build upgrade recommendation if EOL or approaching EOL (< 180 days)
    needs_upgrade = is_eol is True or (isinstance(d_to_eol, int) and d_to_eol < 180)

    recommended = ""
    alternatives = ""
    if needs_upgrade:
        rec_release = get_recommended_release(product_slug, description)
        # Only recommend if it's a *different* release than the current one
        if rec_release and rec_release.get("name") != release.get("name"):
            recommended = _format_release_rec(product_slug, rec_release)

        alts = get_alternatives(product_slug)
        if alts:
            alternatives = _format_alternatives(alts)

    return {
        "product":      product_slug,
        "release":      release.get("label", release.get("name", "")),
        "eol_date":     eol_from,
        "is_eol":       is_eol,
        "days_to_eol":  d_to_eol,
        "recommended":  recommended,
        "alternatives": alternatives,
    }


# ── Main ───────────────────────────────────────────────────────
print("Fetching product catalog from endoflife.date ...")
fetch_product_catalog()

with open(INPUT_FILE, newline="", encoding="utf-8-sig") as f_in:
    reader = csv.DictReader(f_in)
    fieldnames = reader.fieldnames + [
        "OS_EOL_Product",    "OS_EOL_Release",    "OS_EOL_Date",
        "OS_EOL_Reached",    "OS_Days_To_EOL",
        "OS_Upgrade_To",     "OS_Alternatives",
        "App_EOL_Product",   "App_EOL_Release",   "App_EOL_Date",
        "App_EOL_Reached",   "App_Days_To_EOL",
        "App_Upgrade_To",    "App_Alternatives",
    ]

    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f_out:
        writer = csv.DictWriter(f_out, fieldnames=fieldnames)
        writer.writeheader()

        for i, row in enumerate(reader, 1):
            os_desc  = row.get("OSDescription", "")
            os_ver   = row.get("OSVersion", "")
            app_name = row.get("ApplicationName", "")
            app_ver  = row.get("ApplicationShortVersion",
                               row.get("ApplicationVersion", ""))

            # ── OS EOL lookup ──
            os_slug = find_product(os_desc)
            os_eol  = eol_result(os_slug, os_ver, os_desc)

            row["OS_EOL_Product"]  = os_eol["product"]
            row["OS_EOL_Release"]  = os_eol["release"]
            row["OS_EOL_Date"]     = os_eol["eol_date"]
            row["OS_EOL_Reached"]  = os_eol["is_eol"]
            row["OS_Days_To_EOL"]  = os_eol["days_to_eol"]
            row["OS_Upgrade_To"]   = os_eol["recommended"]
            row["OS_Alternatives"] = os_eol["alternatives"]

            # ── App EOL lookup ──
            app_slug = find_product(app_name)
            app_eol  = eol_result(app_slug, app_ver)

            row["App_EOL_Product"]  = app_eol["product"]
            row["App_EOL_Release"]  = app_eol["release"]
            row["App_EOL_Date"]     = app_eol["eol_date"]
            row["App_EOL_Reached"]  = app_eol["is_eol"]
            row["App_Days_To_EOL"]  = app_eol["days_to_eol"]
            row["App_Upgrade_To"]   = app_eol["recommended"]
            row["App_Alternatives"] = app_eol["alternatives"]

            writer.writerow(row)

            # ── Console output ──
            os_rec  = f" -> UPGRADE: {os_eol['recommended']}" if os_eol["recommended"] else ""
            app_rec = f" -> UPGRADE: {app_eol['recommended']}" if app_eol["recommended"] else ""
            print(
                f"Row {i}: OS={os_desc}({os_ver}) "
                f"EOL:{os_eol['is_eol']} days:{os_eol['days_to_eol']}{os_rec}"
            )
            print(
                f"         App={app_name}({app_ver}) "
                f"EOL:{app_eol['is_eol']} days:{app_eol['days_to_eol']}{app_rec}"
            )
            if os_eol["alternatives"]:
                print(f"         OS  Alternatives: {os_eol['alternatives']}")
            if app_eol["alternatives"]:
                print(f"         App Alternatives: {app_eol['alternatives']}")

print(f"\nDone — results written to {OUTPUT_FILE}")
