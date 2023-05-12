const { EventEmitter } = require('events')
const BufferMap = require('tiny-buffer-map')
const sodium = require('sodium-universal')
const crypto = require('hypercore-crypto')
const b4a = require('b4a')
const c = require('compact-encoding')

const {
  Invite,
  InvitePayload,
  InviteRequest,
  InviteResponse,
  InviteData,
  AuthData
} = require('./lib/messages')

const [
  NS_SIGNATURE,
  NS_INVITE_ID,
  NS_TOKEN,
  NS_ENCRYPT,
  NS_NONCE
] = crypto.namespace('keet-pairing', 5)

class ClientRequest extends EventEmitter {
  constructor (discoveryKey, seed, userData) {
    super()

    this.discoveryKey = discoveryKey
    this.seed = seed

    this.keyPair = getKeyPair(seed)
    this.userData = userData || null
    this.id = inviteId(this.keyPair.publicKey)

    this.token = createToken(seed, userData)
    this.payload = createAuth(this.userData, this.token, this.keyPair)

    this.key = null
  }

  _handleResponse (payload) {
    try {
      this._openResponse(payload)
    } catch (err) {
      return this.emit('rejected', err)
    }

    this._onAccept()
  }

  _openResponse (payload) {
    try {
      this.key = openReply(payload, this.token, this.keyPair.publicKey)
    } catch {
      throw new Error('Could not decrypt reply.')
    }

    if (b4a.compare(crypto.discoveryKey(this.key), this.discoveryKey)) {
      this.key = null
      throw new Error('Invite response does not match discoveryKey')
    }
  }

  _onAccept () {
    this.emit('accepted', this.key)
    this.destroy()
  }

  destroy () {
    this.token = null
    this.payload = null

    this.emit('destroyed')
  }
}

class PairingRequest {
  constructor (discoveryKey, inviteId, payload) {
    this.discoveryKey = discoveryKey
    this.id = inviteId
    this.payload = payload

    this.key = null
    this._confirmed = false
    this._denied = false

    // set in open
    this.userData = null
    this.token = null
    this.receipt = null

    this.reply = null
    this.response = null
  }

  static from (req) {
    if (b4a.isBuffer(req)) {
      return PairingRequest.from(c.decode(InviteRequest, req))
    }

    return new PairingRequest(
      req.discoveryKey,
      req.id,
      req.payload
    )
  }

  confirm () {
    if (this._confirmed || this._denied) return
    this._confirmed = true

    this._respond()
  }

  deny () {
    if (this._confirmed || this._denied) return
    this._denied = true

    this._respond()
  }

  _respond () {
    this.response = {
      discoveryKey: this.discoveryKey,
      id: this.id,
      payload: this._confirmed ? this.reply : null
    }
  }

  open (publicKey) {
    const payload = this.payload

    try {
      const { userData, token } = openAuth(payload, publicKey)
      this.userData = userData
      this.token = token
    } catch (e) {
      // todo: log error
      return null
    }

    this.receipt = c.encode(InvitePayload, payload)
    this.reply = createReply(this.key, this.token, publicKey)

    return this.userData
  }
}

class KeetPairing {
  static InviteRequest = InviteRequest
  static InviteResponse = InviteResponse

  constructor () {
    this._requestsByInviteId = new BufferMap()
    this._joinedKeysByDKey = new BufferMap()
  }

  handleRequest (request) {
    const req = PairingRequest.from(request)

    const key = this._joinedKeysByDKey.get(req.discoveryKey)
    if (!key) return

    req.key = key

    return req
  }

  handleResponse (res) {
    const req = this._requestsByInviteId.get(res.id)
    if (!req) return

    req._handleResponse(res.payload)
  }

  join (key) {
    const discoveryKey = crypto.discoveryKey(key)
    if (this._joinedKeysByDKey.has(discoveryKey)) throw new Error('Key is already joined')

    this._joinedKeysByDKey.set(discoveryKey, key)
  }

  leave (key) {
    const discoveryKey = crypto.discoveryKey(key)
    if (!this._joinedKeysByDKey.has(discoveryKey)) throw new Error('Key is not joined')

    this._joinedKeysByDKey.delete(discoveryKey)
  }

  pair (raw, { userData }) {
    const invite = KeetPairing.decodeInvite(raw)

    let request = this._requestsByInviteId.get(invite.id)
    if (!request) {
      request = new ClientRequest(
        invite.discoveryKey,
        invite.seed,
        userData
      )

      this._requestsByInviteId.set(request.id, request)

      request.once('destroyed', () => {
        this._requestsByInviteId.delete(request.id)
      })
    }

    return request
  }

  * requests () {
    yield * this._requestsByInviteId.values()
  }

  static createInvite (key) {
    return createInvite(key)
  }

  static decodeInvite (raw) {
    try {
      return c.decode(Invite, raw)
    } catch {
      throw new Error('Invalid invitation')
    }
  }

  static openRequest (request, publicKey) {
    const payload = c.decode(InvitePayload, request)
    try {
      const { userData } = openAuth(payload, publicKey)
      return userData
    } catch (e) {
      // todo: log error
      return null
    }
  }
}

module.exports.KeetPairing = KeetPairing

function hash (ns, buf, len = 32) {
  const out = b4a.allocUnsafe(len)
  sodium.crypto_generichash_batch(out, [
    ns,
    buf
  ])
  return out
}

function inviteId (publicKey) {
  return hash(NS_INVITE_ID, publicKey)
}

function createToken (seed, userData) {
  const data = b4a.concat([seed, userData])
  return hash(NS_TOKEN, data, sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES)
}

function deriveKey (publicKey) {
  return hash(NS_ENCRYPT, publicKey, sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES)
}

function getNonce (publicKey, token) {
  const data = b4a.concat([publicKey, token])
  return hash(NS_NONCE, data, sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES)
}

function createInvite (key) {
  const discoveryKey = crypto.discoveryKey(key)
  const seed = crypto.randomBytes(32)
  const keyPair = getKeyPair(seed)

  const id = inviteId(keyPair.publicKey)

  return {
    id,
    invite: c.encode(Invite, { discoveryKey, seed }),
    publicKey: keyPair.publicKey
  }
}

function getKeyPair (seed) {
  const publicKey = b4a.allocUnsafe(sodium.crypto_sign_PUBLICKEYBYTES)
  const secretKey = b4a.allocUnsafe(sodium.crypto_sign_SECRETKEYBYTES)

  sodium.crypto_sign_seed_keypair(publicKey, secretKey, seed)
  sodium.crypto_sign_seed_keypair(publicKey, secretKey, seed)

  return { publicKey, secretKey }
}

function encrypt (data, nonce, secretKey) {
  const output = b4a.allocUnsafe(data.byteLength + sodium.crypto_aead_xchacha20poly1305_ietf_ABYTES)
  sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(output, data, nonce, null, nonce, secretKey)
  return output
}

function decrypt (data, nonce, secretKey) {
  const output = b4a.allocUnsafe(data.byteLength - sodium.crypto_aead_xchacha20poly1305_ietf_ABYTES)
  sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(output, null, data, nonce, nonce, secretKey)
  return output
}

function createAuth (userData, token, invitationKeyPair) {
  const secret = deriveKey(invitationKeyPair.publicKey)

  const nonce = getNonce(invitationKeyPair.publicKey, token)
  const signData = c.encode(AuthData, { userData, token })
  const signature = createSignature(signData, invitationKeyPair.secretKey)

  const inviteData = c.encode(InviteData, { userData, signature })
  const data = encrypt(inviteData, nonce, secret)

  return {
    token,
    data
  }
}

function openAuth (payload, invitationKey) {
  const secret = deriveKey(invitationKey)

  const { token, data } = payload

  const nonce = getNonce(invitationKey, token)

  let plaintext
  try {
    plaintext = decrypt(data, nonce, secret)
  } catch {
    // todo stronger check
    throw new Error('Decryption failed.')
  }

  const { userData, signature } = c.decode(InviteData, plaintext)
  const signData = c.encode(AuthData, { userData, token })

  if (!verifySignature(signData, signature, invitationKey)) {
    throw new Error('Invalid signature')
  }

  return {
    token,
    userData
  }
}

function createReply (payload, token, invitationKey) {
  const sessionKey = b4a.concat([invitationKey, token])
  const secret = deriveKey(sessionKey)
  const nonce = getNonce(sessionKey, token)

  return encrypt(payload, nonce, secret)
}

function openReply (data, token, invitationKey) {
  const sessionKey = b4a.concat([invitationKey, token])
  const secret = deriveKey(sessionKey)
  const nonce = getNonce(sessionKey, token)

  return decrypt(data, nonce, secret)
}

function createSignature (data, secretKey) {
  const signature = b4a.allocUnsafe(sodium.crypto_sign_BYTES)
  const namespaced = b4a.allocUnsafe(32 + data.byteLength)

  namespaced.set(NS_SIGNATURE, 0)
  namespaced.set(data, 32)

  sodium.crypto_sign_detached(signature, namespaced, secretKey)

  return signature
}

function verifySignature (data, signature, publicKey) {
  const namespaced = b4a.allocUnsafe(32 + data.byteLength)

  namespaced.set(NS_SIGNATURE, 0)
  namespaced.set(data, 32)

  return sodium.crypto_sign_verify_detached(signature, namespaced, publicKey)
}
