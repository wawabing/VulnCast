import { EpssService } from './epssService.js';

/**
 * CVE Service - Fetches CPE and CVE data for applications
 */

export class CveService {
    constructor() {
        // NVD API keys loaded from env. NVD_API_KEYS is a comma-separated list
        // for rotation on rate limit; falls back to single NVD_API_KEY.
        const keysEnv = process.env.NVD_API_KEYS || process.env.NVD_API_KEY || "";
        this.apiKeys = keysEnv.split(",").map(k => k.trim()).filter(Boolean);
        if (this.apiKeys.length === 0) {
            console.warn("⚠️  No NVD API keys set — rate limits will be severe. Set NVD_API_KEYS in .env");
        }
        this.currentKeyIndex = 0;
        this.cpeUrl = "https://services.nvd.nist.gov/rest/json/cpes/2.0";
        this.cveUrl = "https://services.nvd.nist.gov/rest/json/cves/2.0";
        this.epssService = new EpssService();
    }

    getCurrentApiKey() {
        return this.apiKeys[this.currentKeyIndex];
    }

    rotateApiKey() {
        this.currentKeyIndex = (this.currentKeyIndex + 1) % this.apiKeys.length;
        const newKey = this.getCurrentApiKey();
        console.log(`🔄 Rotating to API key: ${newKey.substring(0, 8)}...`);
        return newKey;
    }

    extractCleanNameAndVersion(name, version) {
        let cleanName = name;

        // Remove any content in parentheses
        cleanName = cleanName.replace(/\s*\([^)]*\)/g, "");

        // Remove architecture suffixes
        const archPatterns = ["x86", "x64", "x86_64", "amd64", "arm", "arm64", "32-bit", "64-bit", "64Bit"];
        const archPattern = new RegExp(`[\\s\\-]?(?:${archPatterns.join('|')})$`, 'i');
        cleanName = cleanName.replace(archPattern, "").trim();

        // Extract version from name if version is unknown
        const versionMatch = cleanName.match(/\b(\d+(?:\.\d+){1,3})\b/);
        if (versionMatch && (version === "Unknown" || !version)) {
            version = versionMatch[1];
            cleanName = cleanName.replace(versionMatch[0], "").trim();
        }

        // Remove version patterns from name
        if (version) {
            const versionPattern = version.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
            cleanName = cleanName.replace(new RegExp(`[\\s\\-]?[vV][\\s\\-]?${versionPattern}`, 'g'), "").trim();
            cleanName = cleanName.replace(new RegExp(`[\\s\\-]*${versionPattern}.*`, 'g'), "").trim();
        }

        // Final cleanup
        cleanName = cleanName.replace(/\s{2,}/g, " ").trim();

        // Use full cleaned name as keyword search for better NVD matching
        // (e.g. "Internet Explorer" instead of just "Internet")
        const words = cleanName.split(/\s+/);
        const targetTerm = cleanName || 'unknown';
        const searchTerms = words;

        return {
            targetTerm,
            version: version || 'Unknown',
            searchTerms
        };
    }

    async delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    async makeApiRequest(url, params, retries = 3) {
        const headers = {};
        const currentKey = this.getCurrentApiKey();
        
        if (currentKey) {
            headers['apikey'] = currentKey;
        }

        for (let attempt = 1; attempt <= retries; attempt++) {
            try {
                const queryString = new URLSearchParams(params).toString();
                const fullUrl = `${url}?${queryString}`;
                
                const response = await fetch(fullUrl, { headers });
                
                if (response.status === 429) {
                    // Rate limited - try rotating to the next API key
                    if (attempt === 1 && this.apiKeys.length > 1) {
                        const newKey = this.rotateApiKey();
                        headers['apikey'] = newKey;
                        continue;
                    }
                    
                    console.log(`⏳ Rate limited, waiting ${attempt * 5} seconds...`);
                    await this.delay(attempt * 5000);
                    continue;
                }
                
                if (response.status === 403) {
                    if (attempt === 1 && this.apiKeys.length > 1) {
                        const newKey = this.rotateApiKey();
                        headers['apikey'] = newKey;
                        continue;
                    }
                    
                    await this.delay(attempt * 10000);
                    continue;
                }
                
                if (!response.ok) {
                    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                }
                
                return await response.json();
            } catch (error) {
                if (attempt === retries) {
                    throw error;
                }
                await this.delay(1000 * attempt);
            }
        }
    }

    async fetchCpesForSoftware(targetTerm, searchTerms) {
        const params = {
            resultsPerPage: 200,
            startIndex: 0,
            keywordSearch: targetTerm
        };

        try {
            const data = await this.makeApiRequest(this.cpeUrl, params);
            const products = data.products || [];
            
            console.log(`Found ${products.length} CPEs for ${targetTerm}`);
            return products;
        } catch (error) {
            console.error(`Failed to fetch CPEs for ${targetTerm}:`, error.message);
            return [];
        }
    }

    scoreCpeEntry(cpeEntry, searchTerms) {
        const cpe = cpeEntry.cpe || {};
        let score = 0;
        const allText = [];

        // Collect all text from titles and references
        (cpe.titles || []).forEach(title => {
            if (title.title) allText.push(title.title);
        });
        
        (cpe.refs || []).forEach(ref => {
            if (ref.ref) allText.push(ref.ref);
        });

        const combined = allText.join(" ").toLowerCase();

        // Score based on search terms
        searchTerms.forEach(term => {
            if (combined.includes(term.toLowerCase())) {
                score += 1;
            }
        });

        return score;
    }

    findBestCpe(products, searchTerms) {
        const uniqueVendorProduct = new Map();
        const counts = new Map();
        const hits = new Map();
        const deprecatedFlags = new Map();

        // Process all products to find unique vendor/product pairs
        products.forEach(item => {
            const cpe = item.cpe || {};
            const cpeName = cpe.cpeName || "";
            const parts = cpeName.split(":");

            // Skip non-application CPEs
            if (parts.length < 11 || parts[2].toLowerCase() !== "a") {
                return;
            }

            const vendor = parts[3];
            const product = parts[4];
            const key = `${vendor}:${product}`;

            // Update counts and hits
            counts.set(key, (counts.get(key) || 0) + 1);
            
            const score = this.scoreCpeEntry(item, searchTerms);
            hits.set(key, (hits.get(key) || 0) + score);

            // Track if ALL entries for this vendor:product are deprecated
            const isDeprecated = cpe.deprecated === true;
            if (!deprecatedFlags.has(key)) {
                deprecatedFlags.set(key, isDeprecated);
            } else if (!isDeprecated) {
                deprecatedFlags.set(key, false); // at least one non-deprecated entry
            }

            // Store the first non-deprecated occurrence, fall back to first overall
            if (!uniqueVendorProduct.has(key)) {
                uniqueVendorProduct.set(key, cpe);
            } else if (!isDeprecated && uniqueVendorProduct.get(key).deprecated === true) {
                uniqueVendorProduct.set(key, cpe); // prefer non-deprecated
            }
        });

        // Find the best match based on hits and count
        let bestMatch = null;
        let bestScore = -1;

        for (const [key, cpe] of uniqueVendorProduct.entries()) {
            const count = counts.get(key) || 0;
            const hitScore = hits.get(key) || 0;
            let totalScore = (hitScore * 3) + count; // Weight hits more heavily

            // Heavily penalise vendor:product pairs where every CPE is deprecated
            if (deprecatedFlags.get(key)) {
                totalScore -= 1000;
            }

            if (totalScore > bestScore) {
                bestScore = totalScore;
                bestMatch = {
                    vendor: key.split(':')[0],
                    product: key.split(':')[1],
                    cpe: cpe,
                    score: totalScore
                };
            }
        }

        return bestMatch;
    }

    async fetchCvesForCpe(cpeName) {
        if (!cpeName) return { cves: [], totalResults: 0 };

        console.log(`Fetching CVEs for CPE: ${cpeName}`);
        
        const params = {
            cpeName: cpeName,
            resultsPerPage: 100,
            startIndex: 0
        };

        try {
            const data = await this.makeApiRequest(this.cveUrl, params);
            const vulnerabilities = data.vulnerabilities || [];
            const totalResults = data.totalResults || vulnerabilities.length;
            
            const cves = vulnerabilities.map(vuln => {
                const cve = vuln.cve || {};
                const cveId = cve.id;
                
                // Get description
                const descriptions = cve.descriptions || [];
                const description = descriptions.find(desc => desc.lang === 'en')?.value || 'No description available';
                
                // Get CVSS data
                const metrics = cve.metrics || {};
                let severity = 'Unknown';
                let score = 'Unknown';
                
                if (metrics.cvssMetricV31 && metrics.cvssMetricV31.length > 0) {
                    const cvss = metrics.cvssMetricV31[0];
                    severity = cvss.cvssData?.baseSeverity || 'Unknown';
                    score = cvss.cvssData?.baseScore || 'Unknown';
                } else if (metrics.cvssMetricV30 && metrics.cvssMetricV30.length > 0) {
                    const cvss = metrics.cvssMetricV30[0];
                    severity = cvss.cvssData?.baseSeverity || 'Unknown';
                    score = cvss.cvssData?.baseScore || 'Unknown';
                } else if (metrics.cvssMetricV2 && metrics.cvssMetricV2.length > 0) {
                    const cvss = metrics.cvssMetricV2[0];
                    severity = cvss.baseSeverity || 'Unknown';
                    score = cvss.cvssData?.baseScore || 'Unknown';
                }
                
                return {
                    cve_id: cveId,
                    description: description,
                    severity: severity,
                    score: score
                };
            });
            
            console.log(`Found ${totalResults} CVEs for ${cpeName} (fetched ${cves.length})`);
            return { cves, totalResults };
        } catch (error) {
            console.error(`Failed to fetch CVEs for ${cpeName}:`, error.message);
            return { cves: [], totalResults: 0 };
        }
    }

    async getCpeAndCvesForApplication(appName, appVersion, appPublisher) {
        try {
            // Clean and extract search terms
            const cleaned = this.extractCleanNameAndVersion(appName, appVersion || 'Unknown');
            
            // Fetch CPEs
            const products = await this.fetchCpesForSoftware(cleaned.targetTerm, cleaned.searchTerms);
            
            if (products.length === 0) {
                return null;
            }

            // Find best matching CPE
            const bestMatch = this.findBestCpe(products, cleaned.searchTerms);
            
            if (!bestMatch) {
                return null;
            }

            const cpeName = bestMatch.cpe.cpeName;
            
            // Fetch CVEs for this CPE
            const { cves, totalResults } = await this.fetchCvesForCpe(cpeName);
            
            // Enrich CVEs with EPSS scores
            const enrichedCves = await this.epssService.enrichCvesWithEpss(cves);
            
            // Rate limiting
            await this.delay(200);
            
            return {
                cpe_name: cpeName,
                vendor: bestMatch.vendor,
                product: bestMatch.product,
                cves: enrichedCves,
                totalCveCount: totalResults
            };

        } catch (error) {
            console.error(`Error getting CPE/CVE data for ${appName}:`, error.message);
            return null;
        }
    }

    /**
     * Get total CVE count for a product by keyword search.
     * Used to fetch real CVE data for EOL alternative products.
     */
    async fetchCveCountByKeyword(keyword) {
        if (!keyword) return 0;
        try {
            const params = { keywordSearch: keyword, resultsPerPage: 1, startIndex: 0 };
            const data = await this.makeApiRequest(this.cveUrl, params);
            return data?.totalResults || 0;
        } catch (error) {
            console.error(`Failed to get CVE count for "${keyword}":`, error.message);
            return 0;
        }
    }
}

export default CveService;