// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/*
 * Re-export all the type definitions that wasm-bindgen generated for us.
 *
 * We do this by referring to a non-existent "matrix_sdk_crypto_wasm.js" file. This works because TSC will automatically
 * transform this into the correct name "matrix_sdk_crypto_wasm.d.ts" [1].
 *
 * Other alternatives don't work:
 *
 *  - `export * from "./pkg/matrix_sdk_crypto_wasm.d.ts"`: You're not allowed to `import from "<foo>.d.ts"`
 *    without `import type`, because normally, that would mean you don't get the runtime definitions that are in
 *    "<foo>.js". This lint rule even applies to ".d.ts" files, which is arguably overzealous, but there you have it.
 *
 *  - `export type * from "./pkg/matrix_sdk_crypto_wasm.d.ts"`: Doing this means you can't call the constructors on any
 *    of the exported types: `new RoomId(...)` gives a build error.
 *
 *  - `export * from "./pkg/matrix_sdk_crypto_wasm"`: This works in *some* environments, but in others, typescript
 *    complains [2]. We could maybe get around this by mandating a `moduleResolution` setting of `bundler` or so, but
 *    that is restrictive on our downstreams.
 *
 * A final alternative would be just to cat `matrix_sdk_crypto_wasm.d.ts` in here as part of the build script, but
 * for now at least we're trying to avoid too much file manipulation.
 *
 * [1]: https://www.typescriptlang.org/docs/handbook/modules/reference.html#file-extension-substitution
 * [2]: https://www.typescriptlang.org/docs/handbook/modules/reference.html#extensionless-relative-paths
 */
export * from "./pkg/matrix_sdk_crypto_wasm.js";

/**
 * Load the WebAssembly module in the background, if it has not already been loaded.
 *
 * Returns a promise which will resolve once the other methods are ready.
 * @param {URL | string} [url] - The URL to fetch the WebAssembly module from. If not provided, a default URL will be used.
 * @returns {Promise<void>}
 */
export declare function initAsync(url?: URL | string): Promise<void>;
