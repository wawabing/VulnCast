/**
 * EPSS Service - Fetches EPSS scores for CVEs
 */

export class EpssService {
    constructor() {
        this.epssUrl = "https://api.first.org/data/v1/epss";
    }

    async delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    async makeApiRequest(url, retries = 3) {
        for (let attempt = 1; attempt <= retries; attempt++) {
            try {
                const response = await fetch(url);
                
                if (response.status === 429) {
                    console.log(`⏳ EPSS Rate limited, waiting ${attempt * 5} seconds...`);
                    await this.delay(attempt * 5000);
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

    async enrichCvesWithEpss(cves) {
        if (!cves || cves.length === 0) return cves;

        try {
            // Get unique CVE IDs
            const cveIds = [...new Set(cves.map(cve => cve.cve_id))];
            
            if (cveIds.length === 0) return cves;

            // Fetch EPSS scores in batches of 100
            const batchSize = 100;
            const allEpssData = new Map();

            for (let i = 0; i < cveIds.length; i += batchSize) {
                const batch = cveIds.slice(i, i + batchSize);
                const cveParam = batch.join(',');
                const url = `${this.epssUrl}?cve=${cveParam}`;

                try {
                    const data = await this.makeApiRequest(url);
                    
                    if (data.data) {
                        data.data.forEach(item => {
                            allEpssData.set(item.cve, {
                                epss_score: parseFloat(item.epss) || 0,
                                epss_percentile: parseFloat(item.percentile) || 0
                            });
                        });
                    }

                    // Rate limiting between batches
                    if (i + batchSize < cveIds.length) {
                        await this.delay(1000);
                    }
                } catch (error) {
                    console.error(`Failed to fetch EPSS for batch ${i}-${i + batchSize}:`, error.message);
                }
            }

            // Enrich CVEs with EPSS data
            return cves.map(cve => ({
                ...cve,
                epss_score: allEpssData.get(cve.cve_id)?.epss_score || 0,
                epss_percentile: allEpssData.get(cve.cve_id)?.epss_percentile || 0
            }));

        } catch (error) {
            console.error('Error enriching CVEs with EPSS:', error.message);
            return cves;
        }
    }
}

export default EpssService;