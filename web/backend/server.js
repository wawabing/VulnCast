import 'dotenv/config';
import express from "express";
import path from "path";
import fs from "fs";
import { fileURLToPath } from 'url';
import session from 'express-session';
import uploadRoutes from "./routes/uploadRoutes.js";
import forecastRoutes from "./routes/forecastRoutes.js";
import sbomRoutes from "./routes/sbomRoutes.js";
import eolRoutes from "./routes/eolRoutes.js";
import { CveService } from "./services/cveService.js";
import { enrichSchema } from "./controllers/uploadController.js";
import { requireAuth, initializeOIDC, getClient, generators } from "./middlewares/auth.js";
import { getJSON, putJSON, getLatestJsonKey, listObjects } from "./services/s3Service.js";
import { getAllCpes } from "./services/dynamoService.js";
import { invokeForecastLambda } from "./services/forecastService.js";

const app = express();
const PORT = process.env.PORT || 3000;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Initialize CVE service
const cveService = new CveService();

// Track enrichment processes
const enrichmentProcesses = new Map();

// Set up EJS
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, '../views'));

// Parse JSON bodies
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session middleware
app.use(session({
  secret: process.env.SESSION_SECRET || 'fallback-secret-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: false, // set to true in production with HTTPS
    maxAge: 1000 * 60 * 60 * 24 // 24 hours
  }
}));

// Make user available to all EJS templates
app.use((req, res, next) => {
  res.locals.user = req.session?.userInfo || null;
  next();
});

// Ensure storage folders exist
const tempDir = path.join(__dirname, "temp-files");
if (!fs.existsSync(tempDir)) fs.mkdirSync(tempDir);

const schemaDir = path.join(__dirname, "visual-schemas");
if (!fs.existsSync(schemaDir)) fs.mkdirSync(schemaDir);

// Serve frontend
app.use(express.static(path.join(__dirname, "../frontend")));

// ─── Auth Routes (public) ───────────────────────────────────────────

// Login – redirect to Cognito Hosted UI via openid-client
app.get('/login', (req, res) => {
  if (req.session?.userInfo) return res.redirect('/dashboard');

  const client = getClient();
  const nonce = generators.nonce();
  const state = generators.state();

  req.session.nonce = nonce;
  req.session.state = state;

  const authUrl = client.authorizationUrl({
    scope: 'phone openid email',
    state,
    nonce,
  });

  res.redirect(authUrl);
});

// Cognito callback – exchange code for tokens via openid-client
app.get('/auth/callback', async (req, res) => {
  try {
    const client = getClient();
    const params = client.callbackParams(req);
    const tokenSet = await client.callback(
      process.env.COGNITO_CALLBACK_URL,
      params,
      {
        nonce: req.session.nonce,
        state: req.session.state,
      }
    );

    // Fetch user info from Cognito
    const userInfo = await client.userinfo(tokenSet.access_token);
    req.session.userInfo = userInfo;

    // Check if user has uploaded data – redirect accordingly
    const userSub = userInfo.sub || "anonymous";
    const schemas = await listObjects(`schemas/${userSub}/`);
    if (schemas.length === 0) {
      res.redirect('/onboarding');
    } else {
      res.redirect('/dashboard');
    }
  } catch (err) {
    console.error('Auth callback error:', err);
    res.redirect('/login');
  }
});

// Logout – destroy session and redirect to Cognito logout endpoint
app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    const logoutUrl = `${process.env.COGNITO_DOMAIN}/logout?client_id=${process.env.COGNITO_APP_CLIENT_ID}&logout_uri=${encodeURIComponent(process.env.COGNITO_LOGOUT_URL)}`;
    res.redirect(logoutUrl);
  });
});

// ─── API Routes ─────────────────────────────────────────────────────
app.use("/api/upload", uploadRoutes);
app.use("/api/forecasts", forecastRoutes);
app.use("/api/sbom", sbomRoutes);
app.use("/api/eol", eolRoutes);

// API: check whether the current user has uploaded data
app.get('/api/user-has-data', requireAuth, async (req, res) => {
  try {
    const userSub = req.session?.userInfo?.sub || "anonymous";
    const schemas = await listObjects(`schemas/${userSub}/`);
    res.json({ hasData: schemas.length > 0 });
  } catch (err) {
    console.error('Error checking user data:', err);
    res.json({ hasData: false });
  }
});

// ─── Protected Page Routes ──────────────────────────────────────────

// Root route – redirect to dashboard if logged in, else login
app.get('/', requireAuth, async (req, res) => {
  const userSub = req.session?.userInfo?.sub || "anonymous";
  const schemas = await listObjects(`schemas/${userSub}/`);
  if (schemas.length === 0) return res.redirect('/onboarding');
  res.redirect('/dashboard');
});

// Onboarding – shown when user has no data yet
app.get('/onboarding', requireAuth, (req, res) => {
  res.render('onboarding');
});

// All these pages require authentication + data check
app.get('/dashboard', requireAuth, async (req, res) => {
  const userSub = req.session?.userInfo?.sub || "anonymous";
  const schemas = await listObjects(`schemas/${userSub}/`);
  if (schemas.length === 0) return res.redirect('/onboarding');
  res.render('dashboard');
});

app.get('/devices', requireAuth, (req, res) => {
  res.render('devices');
});

app.get('/users', requireAuth, (req, res) => {
  res.render('users');
});

app.get('/applications', requireAuth, (req, res) => {
  res.render('applications');
});

app.get('/vulnerabilities', requireAuth, (req, res) => {
  res.render('vulnerabilities');
});

app.get('/forecast', requireAuth, (req, res) => {
  res.render('forecast');
});

app.get('/supply-chain', requireAuth, (req, res) => {
  res.render('supply-chain', { activeNav: 'supply-chain' });
});

app.get('/processing', requireAuth, (req, res) => {
  res.render('processing');
});

app.get('/profile', requireAuth, (req, res) => {
  res.render('profile');
});

// API endpoint to get the latest schema (from S3)
app.get('/api/latest-schema', async (req, res) => {
  try {
    const userSub = req.session?.userInfo?.sub || "anonymous";
    const prefix = `schemas/${userSub}/`;

    const latestKey = await getLatestJsonKey(prefix);
    if (!latestKey) {
      return res.status(404).json({ error: 'No schema files found' });
    }

    const schema = await getJSON(latestKey);
    res.json({ success: true, schema, schemaKey: latestKey });
  } catch (error) {
    console.error('Error reading schema from S3:', error);
    res.status(500).json({ success: false, error: 'Error reading schema file' });
  }
});

// API endpoint to enrich the latest schema with CVE data (via S3)
app.post('/api/enrich-cves', async (req, res) => {
  try {
    const userSub = req.session?.userInfo?.sub || "anonymous";
    const prefix = `schemas/${userSub}/`;

    const latestKey = await getLatestJsonKey(prefix);
    if (!latestKey) {
      return res.status(404).json({ success: false, error: 'No schema files found' });
    }

    const enrichedSchema = await enrichSchema(latestKey, userSub);

    res.json({
      success: true,
      message: 'CVE enrichment completed',
      enriched_applications: enrichedSchema.applications?.length || 0,
    });

  } catch (error) {
    console.error('Error during CVE enrichment:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// API endpoint to start enrichment process (async with progress tracking)
app.post('/api/start-enrichment', async (req, res) => {
  const { schemaKey } = req.body;

  if (!schemaKey) {
    return res.status(400).json({ success: false, error: 'schemaKey required' });
  }

  try {
    const userSub = req.session?.userInfo?.sub || "anonymous";

    // Initialize process tracking
    enrichmentProcesses.set(schemaKey, {
      status: 'starting',
      progress: 0,
      step: 1,
      startTime: new Date()
    });

    // Start enrichment asynchronously
    enrichSchema(schemaKey, userSub)
      .then(() => {
        enrichmentProcesses.set(schemaKey, {
          status: 'completed',
          progress: 100,
          step: 5,
          completedTime: new Date()
        });
      })
      .catch((error) => {
        enrichmentProcesses.set(schemaKey, {
          status: 'error',
          progress: 0,
          step: 1,
          error: error.message
        });
      });

    res.json({ success: true, message: 'Enrichment started' });

  } catch (error) {
    console.error('Error starting enrichment:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// API endpoint to get enrichment progress
app.get('/api/enrichment-progress', (req, res) => {
  const { schemaKey } = req.query;

  if (!schemaKey) {
    return res.status(400).json({ success: false, error: 'schemaKey required' });
  }

  const process = enrichmentProcesses.get(schemaKey);

  if (!process) {
    return res.json({
      success: true,
      status: 'not_found',
      progress: 0,
      step: 1
    });
  }

  let progress = process.progress;
  let step = process.step;

  if (process.status === 'starting') {
    progress = Math.min(20, progress + 5);
    step = 2;
  } else if (process.status === 'processing') {
    progress = Math.min(80, progress + 10);
    step = Math.min(4, Math.floor(progress / 20) + 1);
  }

  enrichmentProcesses.set(schemaKey, { ...process, progress, step });

  res.json({
    success: true,
    status: process.status,
    progress,
    step,
    error: process.error
  });
});

// API endpoint to list all CPEs in the forecast table
app.get('/api/forecast-cpes', async (req, res) => {
  try {
    const cpes = await getAllCpes();
    res.json({ success: true, cpes });
  } catch (error) {
    console.error('Error fetching forecast CPEs:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// API endpoint to trigger the forecast Lambda after a new data upload
app.post('/api/trigger-forecast', requireAuth, async (req, res) => {
  try {
    const result = await invokeForecastLambda();
    res.json({ success: true, message: 'Forecast Lambda triggered', statusCode: result.statusCode });
  } catch (error) {
    console.error('Error triggering forecast Lambda:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Catch-all for frontend
app.use(requireAuth, async (req, res) => {
  const userSub = req.session?.userInfo?.sub || "anonymous";
  const schemas = await listObjects(`schemas/${userSub}/`);
  if (schemas.length === 0) return res.redirect('/onboarding');
  res.render('index');
});

// Initialize OIDC client then start server
initializeOIDC()
  .then(() => {
    app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
  })
  .catch((err) => {
    console.error('Failed to initialize OIDC client:', err);
    process.exit(1);
  });
