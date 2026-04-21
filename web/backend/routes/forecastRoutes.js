import express from "express";
import { getForecasts, getForecast, getYearlyForecastRoute } from "../controllers/forecastController.js";

const router = express.Router();

// GET /api/forecasts — all forecasts + summary
router.get("/", getForecasts);

// GET /api/forecasts/yearly/:year — yearly total CVE forecast
router.get("/yearly/:year", getYearlyForecastRoute);

// GET /api/forecasts/:cpe — single CPE forecast (URL-encoded CPE string)
router.get("/:cpe", getForecast);

export default router;
