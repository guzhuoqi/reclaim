#!/usr/bin/env node
/*
 Minimal WSS attestor caller for Python addon
 Usage:
   node call-attestor-wss.js --params '<json>' --secretParams '<json>' --clientUrl 'wss://host/ws'
 Env:
   PRIVATE_KEY required
 Output: single line JSON
*/

const path = require('path')

function exitWithError(err) {
  const out = JSON.stringify({ success: false, error: err && err.message ? err.message : String(err) })
  process.stdout.write(out)
  process.exit(1)
}

async function main() {
  try {
    const args = process.argv.slice(2)
    let params = {}
    let secretParams = {}
    let clientUrl = ''
    let noAuth = false

    for (let i = 0; i < args.length; i += 2) {
      const key = args[i]
      const value = args[i + 1]
      if (!value) continue
      switch (key) {
        case '--params':
          params = JSON.parse(value)
          break
        case '--secretParams':
          secretParams = JSON.parse(value)
          break
        case '--clientUrl':
          clientUrl = value
          break
        case '--noAuth':
          noAuth = true
          i -= 1
          break
      }
    }

    if (!clientUrl) throw new Error('missing --clientUrl')
    if (!params || !params.url || !params.method) throw new Error('missing params.url or params.method')
    const pk = process.env.PRIVATE_KEY
    if (!pk) throw new Error('missing env PRIVATE_KEY')

    // Use compiled attestor-core lib
    const clientModPath = path.resolve(__dirname, '../../attestor-core/lib/client/index.js')
    const authModPath = path.resolve(__dirname, '../../attestor-core/lib/utils/auth.js')
    const { createClaimOnAttestor } = require(clientModPath)
    const { createAuthRequest } = require(authModPath)

    const logger = { child: () => logger, info(){}, debug(){}, trace(){}, warn(){}, error(){}, fatal(){} }

    const authRequest = noAuth ? undefined : await createAuthRequest({ id: 'mitmproxy-addon', hostWhitelist: [] }, pk)

    async function runOnce(withAuth) {
      return await createClaimOnAttestor({
        name: 'http',
        params,
        secretParams,
        ownerPrivateKey: pk,
        client: (withAuth && authRequest) ? { url: clientUrl, authRequest } : { url: clientUrl },
        logger
      })
    }

    let receipt
    try {
      receipt = await runOnce(!noAuth)
    } catch (e) {
      const msg = (e && e.message) ? e.message : String(e)
      // If server not configured for auth, retry without auth
      if (!noAuth && /not configured for authentication/i.test(msg)) {
        receipt = await runOnce(false)
      } else {
        throw e
      }
    }

    const result = {
      success: true,
      receipt: JSON.parse(JSON.stringify(receipt)),
      timestamp: Math.floor(Date.now() / 1000)
    }
    process.stdout.write(JSON.stringify(result))
    process.exit(0)
  } catch (err) {
    exitWithError(err)
  }
}

main()


