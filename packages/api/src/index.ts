// See tsup.config.ts for additional banner/footer js
import * as NearGlobal from "./near";
export * from "./near.js";

declare global {
  interface Window {
    near: typeof NearGlobal;

    // $$: typeof NearGlobal.utils.convertUnit;
  }
}