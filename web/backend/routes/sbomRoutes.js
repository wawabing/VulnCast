import express from "express";
import multer from "multer";
import {
  uploadAndAnalyse,
  getManifestRoute,
  getScanResults,
  deleteScan,
} from "../controllers/sbomController.js";

const router = express.Router();

// Multer — memory storage (buffer goes straight to S3)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024 }, // 50 MB
  fileFilter: (_req, file, cb) => {
    const ext = file.originalname.split(".").pop().toLowerCase();
    if (["json", "xml", "spdx", "cdx"].includes(ext)) cb(null, true);
    else cb(new Error("Only JSON, XML, SPDX, and CDX files are accepted"), false);
  },
});

// POST /api/sbom/upload  — upload + parse + OSV scan + store to S3
router.post("/upload", upload.single("sbom"), uploadAndAnalyse);

// GET  /api/sbom/manifest — user's full SBOM manifest + coverage
router.get("/manifest", getManifestRoute);

// GET  /api/sbom/results/:scanId — individual scan detail
router.get("/results/:scanId", getScanResults);

// DELETE /api/sbom/scans/:scanId — remove a scan
router.delete("/scans/:scanId", deleteScan);

export default router;
