/** Where a secret is stored. Used for `--breached` filtering. */
export type Platform = 'env' | 'github' | 'vercel' | 'railway' | 'list';

/** One sighting of an env var name in one place. */
export interface Sighting {
  name: string;
  platform: Platform;
  /** Human label, e.g. ".env.local" or "vercel:shop (production, preview)". */
  location: string;
  /** Only known for local sources (env files, Railway export). Never printed. */
  value?: string;
}

export type Priority = 'high' | 'medium' | 'low';

export type VerifyStatus = 'dead' | 'live' | 'unknown' | 'manual' | 'no-value' | 'placeholder';

export interface VerifyResult {
  status: VerifyStatus;
  detail: string;
}

export type FetchLike = (url: string, init?: RequestInit) => Promise<Response>;

export interface Issuer {
  id: string;
  name: string;
  priority: Priority;
  /** Tested against the upper-cased var name. */
  names: RegExp[];
  /** Tested against the value, when the value is known. */
  values?: RegExp[];
  rotateUrl?: string;
  steps: string[];
  /** Automatic check with a read-only auth endpoint. */
  verify?: (value: string, fetch: FetchLike) => Promise<VerifyResult>;
  /** Shown when there is no automatic check. */
  manualCheck?: string;
}

export interface Secret {
  name: string;
  issuer: Issuer;
  matchedBy: 'name' | 'value' | 'none';
  priority: Priority;
  /** Name looks like plain config (PORT, NODE_ENV...), not a secret. */
  config: boolean;
  /** NEXT_PUBLIC_ / VITE_ / ... : already shipped to the browser. */
  public: boolean;
  sightings: Sighting[];
  warnings: string[];
}
