import express from "express";
import multer from "multer";
import { handleUpload } from "../controllers/uploadController.js";

const router = express.Router();

// Use memory storage – file buffer goes straight to S3, not disk
const upload = multer({ storage: multer.memoryStorage() });

// POST /api/upload
router.post("/", upload.single("file"), handleUpload);

export default router;
