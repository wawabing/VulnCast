import CveService from './services/cveService.js';
const svc = new CveService();

// Override to get more results
const origMakeReq = svc.makeApiRequest.bind(svc);
svc.fetchCpesForSoftware = async function(targetTerm, searchTerms) {
  const params = { resultsPerPage: 200, startIndex: 0, keywordSearch: targetTerm };
  const data = await origMakeReq(this.cpeUrl, params);
  const products = data.products ? data.products : [];
  console.log(`Found ${products.length} CPEs (total ${data.totalResults}) for ${targetTerm}`);
  return products;
};

const products = await svc.fetchCpesForSoftware('Internet Explorer', ['internet', 'explorer']);
const vendors = new Map();
products.forEach(item => {
  const cpe = item.cpe ? item.cpe : {};
  const parts = (cpe.cpeName ? cpe.cpeName : '').split(':');
  if (parts.length < 11) return;
  const key = parts[3] + ':' + parts[4];
  if (!vendors.has(key)) vendors.set(key, { count: 0, deprecated: [], sample: cpe.cpeName });
  const entry = vendors.get(key);
  entry.count++;
  entry.deprecated.push(cpe.deprecated === true);
});
for (const [key, info] of vendors) {
  const depCount = info.deprecated.filter(Boolean).length;
  console.log(key, '| count:', info.count, '| deprecated:', depCount + '/' + info.deprecated.length, '| sample:', info.sample);
}
