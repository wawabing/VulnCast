import { Issuer, generators, custom } from "openid-client";

let client;

/**
 * Initialize the OpenID Connect client by discovering the Cognito issuer.
 * Must be called once at startup before any auth routes are used.
 */
export async function initializeOIDC() {
  // Increase default timeout from 3500ms to 10000ms
  Issuer[custom.http_options] = () => ({ timeout: 10000 });

  const issuer = await Issuer.discover(process.env.COGNITO_ISSUER);
  client = new issuer.Client({
    client_id: process.env.COGNITO_APP_CLIENT_ID,
    client_secret: process.env.COGNITO_APP_CLIENT_SECRET,
    redirect_uris: [process.env.COGNITO_CALLBACK_URL],
    response_types: ["code"],
  });
  console.log("OpenID Connect client initialized");
  return client;
}

/**
 * Returns the initialized OIDC client.
 */
export function getClient() {
  if (!client) throw new Error("OIDC client not initialized — call initializeOIDC() first");
  return client;
}

/**
 * Returns the openid-client generators (nonce, state).
 */
export { generators };

/**
 * Express middleware: redirects to /login if the user is not authenticated.
 */
export function requireAuth(req, res, next) {
  if (req.session && req.session.userInfo) {
    res.locals.user = req.session.userInfo;
    return next();
  }
  res.redirect("/login");
}
