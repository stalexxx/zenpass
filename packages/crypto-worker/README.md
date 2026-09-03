# crypto-worker

Worker-side protocol host for `crypto-wasm`. Send only the discriminated
`CryptoRequest` messages and treat `lock` as terminal for all issued sessions.
The protocol deliberately rejects unknown fields and has no raw-key message.
