// Deployment settings. Both values are public by design: the publishable key
// only allows what the database's row-level security policies permit.
//
// Leave SUPABASE_URL empty to run in demo mode: data stays in this browser and
// AI uses the API key entered in Settings. See docs/deploy.md.
//
// The /demo address (demo/index.html) always runs in demo mode, even though the
// rest of the site uses the hosted database.
const DEMO_PATH = typeof location !== "undefined" && /^\/demo(\/|$)/.test(location.pathname);
export const SUPABASE_URL = DEMO_PATH ? "" : "https://nkqezgylrsokvsvfnaoj.supabase.co";
// From Supabase: Project Settings → API Keys → "Publishable key" (sb_publishable_…).
// Older projects can use the legacy "anon" key instead. Never use a secret or service_role key.
export const SUPABASE_PUBLISHABLE_KEY = "sb_publishable_GKatpIm4N_Q8fnf273kKbw_FaoZx5dk";

// Signed-in users are signed out after this many minutes without activity.
export const IDLE_TIMEOUT_MINUTES = 30;
