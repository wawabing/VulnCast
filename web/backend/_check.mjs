import { getJSON, getLatestJsonKey } from './services/s3Service.js';
import { getForecastSummary } from './services/forecastService.js';

// Check forecasts
const summary = await getForecastSummary();
console.log('=== FORECASTS ===');
console.log('Total:', summary.total, '| success:', summary.successCount, '| failed:', summary.failedCount);
console.log('totalPredicted:', summary.totalPredicted, '| totalActual:', summary.totalActual);
console.log('Growth:', summary.avgDiffPct);
if (summary.successful) {
  summary.successful.forEach(f => {
    console.log('  CPE:', f.cpe ? f.cpe.substring(0, 60) : 'none', '| predicted:', f.forecast_total, '| actual:', f.backtest_actual_total);
  });
}
if (summary.failed) {
  summary.failed.forEach(f => {
    console.log('  FAILED:', f.cpe ? f.cpe.substring(0, 60) : 'none');
  });
}
