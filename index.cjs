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

// @ts-check

/**
 * This is the entrypoint on non-node CommonJS environments.
 * `asyncLoad` will load the WASM module using a `fetch` call.
 */

const bindings = require("./pkg/matrix_sdk_crypto_wasm_bg.cjs");

const defaultURL = require.resolve("./pkg/matrix_sdk_crypto_wasm_bg.wasm");

// We want to throw an error if the user tries to use the bindings before
// calling `initAsync`.
bindings.__wbg_set_wasm(
    new Proxy(
        {},
        {
            get() {
                throw new Error(
                    "@matrix-org/matrix-sdk-crypto-wasm was used before it was initialized. Call `initAsync` first.",
                );
            },
        },
    ),
);

/**
 * Stores a promise of the `loadModule` call
 * @type {Promise<void> | null}
 */
let modPromise = null;

/**
 * Loads and instantiates the WASM module asynchronously
 *
 * @param {URL | string} url - The URL to fetch the WebAssembly module from
 * @returns {Promise<void>}
 */
async function loadModuleAsync(url) {
    const { instance } = await WebAssembly.instantiateStreaming(fetch(url), {
        // @ts-expect-error: The bindings don't exactly match the 'ExportValue' type
        "./matrix_sdk_crypto_wasm_bg.js": bindings,
    });

    bindings.__wbg_set_wasm(instance.exports);
    // @ts-expect-error: Typescript doesn't know what the module exports are
    instance.exports.__wbindgen_start();
}

/**
 * Load the WebAssembly module in the background, if it has not already been loaded.
 *
 * Returns a promise which will resolve once the other methods are ready.
 *
 * @param {URL | string} [url] - The URL to fetch the WebAssembly module from. If not provided, a default URL will be used.
 * @returns {Promise<void>}
 */
async function initAsync(url = defaultURL) {
    if (!modPromise) modPromise = loadModuleAsync(url);
    await modPromise;
}

module.exports = {
    // Re-export everything from the generated javascript wrappers
    ...bindings,
    initAsync,
};
