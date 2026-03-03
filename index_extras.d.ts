/*
Copyright 2026 The Matrix.org Foundation C.I.C.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/* This file exists to support `index.d.ts`. It adds some backwards-compatibility exports for renamed types.
 *
 * Ideally we'd do this inline in `index.d.ts`, but that seems to confuse `typedoc` (it ends up suppressing the
 * documentation for the proper type).
 */

/** @deprecated Exported for backwards-compatibility only. Use {@link QrCodeIntent} instead. */
export { QrCodeIntent as QrCodeMode } from "./pkg/matrix_sdk_crypto_wasm.js";
