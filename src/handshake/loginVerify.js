const JWT = require('jsonwebtoken')
const constants = require('./constants')
const debug = require('debug')('minecraft-protocol')
const crypto = require('crypto')

module.exports = (client, server, options) => {
  // Refer to the docs:
  // https://web.archive.org/web/20180917171505if_/https://confluence.yawk.at/display/PEPROTOCOL/Game+Packets#GamePackets-Login

  const getDER = b64 => crypto.createPublicKey({ key: Buffer.from(b64, 'base64'), format: 'der', type: 'spki' })

  // Check if a string looks like a valid JWT token (has at least header.payload.signature)
  function isValidJWT(str) {
    if (!str || typeof str !== 'string') return false
    if (str.length < 10) return false
    const parts = str.split('.')
    if (parts.length < 2) return false
    try {
      const header = Buffer.from(parts[0], 'base64').toString('utf-8')
      JSON.parse(header)
      return true
    } catch {
      return false
    }
  }

  // 26.10, March 2026+
  // Handles the new LoginToken format:
  //   RS256 (online/full)  — header has { alg: "RS256", kid: "...", typ: "JWT" }, no x5u
  //   ES384 (self-signed)  — header has { alg: "ES384", x5u: "..." }
  function parseLoginToken(token) {
    function normalizeToken(token) {
      return token.replace(/^MCToken\s+/i, '')
    }

    const normalized = normalizeToken(token)
    const [headerB64] = normalized.split('.')
    const headerStr = Buffer.from(headerB64, 'base64').toString('utf-8')
    const header = JSON.parse(headerStr)

    if (header.alg === 'RS256') {
      // Online / full authentication token (OIDC).
      // Relay mode: decode without signature verification — the destination server
      // will verify. We only need to extract identity data for forwarding.
      const decoded = JWT.decode(normalized)
      if (!decoded || typeof decoded !== 'object') throw new Error('Invalid RS256 login token')

      const payload = decoded
      const key = payload.cpk || payload.clientPublicKey || ''
      return {
        key,
        data: {
          extraData: {
            XUID: payload.xid || payload.XUID || payload.xuid || '0',
            displayName: payload.xname || payload.displayName || 'Player',
            identity: payload.identity,
            PlayFabID: payload.pfbid || payload.playFabId || payload.PlayFabID,
            PlayFabTitleID: payload.pfbtid || payload.playFabTitleId || payload.PlayFabTitleID
          }
        }
      }
    }

    if (header.alg === 'ES384') {
      // Self-signed authentication token — verify with x5u
      const x5u = getX5U(normalized)
      const decoded = JWT.verify(normalized, getDER(x5u), { algorithms: ['ES384', 'RS256'] })
      if (!decoded || typeof decoded !== 'object') throw new Error('Invalid login token')

      const payload = decoded || {}
      const key = payload.cpk || payload.clientPublicKey || x5u
      return {
        key,
        data: {
          extraData: {
            XUID: payload.xid || payload.XUID || payload.xuid || '0',
            displayName: payload.xname || payload.displayName || 'Player',
            identity: payload.identity,
            PlayFabID: payload.pfbid || payload.playFabId || payload.PlayFabID,
            PlayFabTitleID: payload.pfbtid || payload.playFabTitleId || payload.PlayFabTitleID
          }
        }
      }
    }

    throw new Error('Unsupported login token algorithm: ' + header.alg)
  }

  // Legacy token data parser (self-signed only, pre-1.26.10)
  function parseTokenData(token) {
    function normalizeToken(token) {
      return token.replace(/^MCToken\s+/i, '')
    }

    const normalized = normalizeToken(token)
    const x5u = getX5U(normalized)
    const decoded = JWT.verify(normalized, getDER(x5u), { algorithms: ['ES384', 'RS256'] })
    if (!decoded || typeof decoded !== 'object') throw new Error('Invalid login token')

    const payload = decoded || {}
    const key = payload.cpk || payload.clientPublicKey || x5u
    return {
      key,
      data: {
        extraData: {
          XUID: payload.xid || payload.XUID || payload.xuid || '0',
          displayName: payload.xname || payload.displayName || 'Player',
          identity: payload.identity,
          PlayFabID: payload.pfbid || payload.playFabId || payload.PlayFabID,
          PlayFabTitleID: payload.pfbtid || payload.playFabTitleId || payload.PlayFabTitleID
        }
      }
    }
  }

  function verifyAuth(chain, token) {
    // Filter out placeholder entries (e.g. ".." sent by 1.26.10+ clients)
    const validChain = chain ? chain.filter(e => isValidJWT(e)) : []

    // 1.26.10+ with a login token: if the legacy chain is all placeholders,
    // or chain is empty/missing, use the authToken directly.
    if ((!chain || chain.length === 0 || validChain.length === 0 || chain.every(entry => !entry)) && token) {
      return parseLoginToken(token)
    }

    let data = {}

    // There are three JWT tokens sent to us, one signed by the client
    // one signed by Mojang with the Mojang token we have and another one
    // from Xbox with addition user profile data
    // We verify that at least one of the tokens in the chain has been properly
    // signed by Mojang by checking the x509 public key in the JWT headers
    let didVerify = false

    let pubKey = getDER(getX5U(validChain[0])) // the first one is client signed, allow it
    let finalKey = null

    for (const t of validChain) {
      const decoded = JWT.verify(t, pubKey, { algorithms: ['ES384'] })

      // Check if signed by Mojang key
      const x5u = getX5U(t)
      if (x5u === constants.PUBLIC_KEY && !data.extraData?.XUID) {
        didVerify = true
        debug('Verified client with mojang key', x5u)
      }

      pubKey = decoded.identityPublicKey ? getDER(decoded.identityPublicKey) : x5u
      finalKey = decoded.identityPublicKey || finalKey // non pem
      data = { ...data, ...decoded }
    }

    if (!didVerify && !options.offline) {
      client.disconnect('disconnectionScreen.notAuthenticated')
    }

    return { key: finalKey, data }
  }

  function verifySkin(publicKey, token) {
    const pubKey = getDER(publicKey)
    const decoded = JWT.verify(token, pubKey, { algorithms: ['ES384'] })
    return decoded
  }

  client.decodeLoginJWT = (authTokens, skinTokens, authToken = '') => {
    const { key, data } = verifyAuth(authTokens, authToken)
    const skinData = verifySkin(key, skinTokens)
    return { key, userData: data, skinData }
  }

  client.encodeLoginJWT = (localChain, mojangChain) => {
    const chains = []
    chains.push(localChain)
    for (const chain of mojangChain) {
      chains.push(chain)
    }
    return chains
  }
}

function getX5U(token) {
  const [header] = token.split('.')
  const hdec = Buffer.from(header, 'base64').toString('utf-8')
  const hjson = JSON.parse(hdec)
  return hjson.x5u
}
