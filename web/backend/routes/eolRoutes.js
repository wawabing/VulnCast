import express from "express";
import { getEolForApps } from "../controllers/eolController.js";

const router = express.Router();

// POST /api/eol — bulk EOL lookup for applications
router.post("/", getEolForApps);

export default router;
