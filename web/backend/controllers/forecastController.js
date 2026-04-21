import {
  getAllForecasts,
  getForecastByCpe,
  getForecastSummary,
  getYearlyForecast,
} from "../services/forecastService.js";

/**
 * GET /api/forecasts — return full summary + all forecast items
 */
export async function getForecasts(req, res) {
  try {
    const summary = await getForecastSummary();
    res.json({ success: true, ...summary });
  } catch (error) {
    console.error("Error fetching forecasts:", error);
    res.status(500).json({ success: false, error: error.message });
  }
}

/**
 * GET /api/forecasts/:cpe — return a single CPE's forecast
 * The CPE is URL-encoded in the path (colons, asterisks, etc.)
 */
export async function getForecast(req, res) {
  try {
    const cpe = decodeURIComponent(req.params.cpe);
    const item = await getForecastByCpe(cpe);

    if (!item) {
      return res.status(404).json({ success: false, error: "CPE not found" });
    }

    res.json({ success: true, forecast: item });
  } catch (error) {
    console.error("Error fetching forecast:", error);
    res.status(500).json({ success: false, error: error.message });
  }
}

/**
 * GET /api/forecasts/yearly/:year — return the yearly total CVE forecast
 */
export async function getYearlyForecastRoute(req, res) {
  try {
    const year = req.params.year;
    const item = await getYearlyForecast(year);

    if (!item) {
      return res.status(404).json({ success: false, error: `No forecast found for year ${year}` });
    }

    res.json({ success: true, forecast: item });
  } catch (error) {
    console.error("Error fetching yearly forecast:", error);
    res.status(500).json({ success: false, error: error.message });
  }
}
