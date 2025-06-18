// See tsup.config.ts for additional banner/footer js
export * from "./near.js";

declare global {
  interface Window {
    near: typeof import("fastintear");

    // $$: typeof NearGlobal.utils.convertUnit;
  }
}

