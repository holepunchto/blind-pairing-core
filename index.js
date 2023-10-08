const { EventEmitter } = require('events')
const sodium = require('sodium-universal')
const crypto = require('hypercore-crypto')
const b4a = require('b4a')
const c = require('compact-encoding')

const {
  Invite,
  RequestPayload,
  ResponsePayload,
  InviteRequest,
  InviteResponse,
  PersistedRequest,
  InviteData,
  AuthData
} = require('./lib/messages')

const [
  NS_SIGNATURE,
  NS_INVITE_ID,
  NS_TOKEN,
  NS_ENCRYPT,
  NS_NONCE
] = crypto.namespace('blind-pairing', 5)

class CandidateRequest extends EventEmitter {
  constructor (invite, userData) {
    super()

    if (b4a.isBuffer(invite)) {
      invite = c.decode(Invite, invite)
    }

    this.discoveryKey = invite.discoveryKey
    this.seed = invite.seed

    this.keyPair = getKeyPair(this.seed)
    this.userData = userData
    this.id = inviteId(this.keyPair.publicKey)

    this.token = createToken(this.seed, userData)
    this.payload = createAuth(this.userData, this.token, this.keyPair)

    this.auth = null

    // set by relay
    this._relaySeq = null
  }

  static encoding = PersistedRequest

  handleResponse (payload) {
    try {
      this._openResponse(payload)
    } catch (err) {
      try {
        const data = this._decodeResponse(payload)
        return this.handleResponse(data)
      } catch {
        this.emit('rejected', err)
        return null
      }
    }

    this._onAccept()
    return this.auth
  }

  _openResponse (payload) {
    try {
      const response = openReply(payload, this.token, this.keyPair.publicKey)
      this.auth = c.decode(ResponsePayload, response)
    } catch {
      throw new Error('Could not decrypt reply.')
    }

    if (b4a.compare(crypto.discoveryKey(this.auth.key), this.discoveryKey)) {
      this.auth = null
      throw new Error('Invite response does not match discoveryKey')
    }
  }

  _onAccept () {
    this.emit('accepted', this.auth)
    this.destroy()
  }

  _decodeResponse (buf) {
    try {
      const { payload } = c.decode(InviteResponse, buf)
      return payload
    } catch {
      throw new Error('Could not decode response.')
    }
  }

  destroy () {
    this.token = null
    this.payload = null

    this.emit('destroyed')
  }

  encode () {
    return c.encode(InviteRequest, this)
  }

  persist () {
    return c.encode(CandidateRequest.encoding, this)
  }

  static from (buf) {
    const info = c.decode(CandidateRequest.encoding, buf)
    const { seed, discoveryKey, userData } = info
    const request = new CandidateRequest({ discoveryKey, seed }, userData)

    // clear completed request
    if (info.key) {
      request.key = info.key
      request.token = null
      request.payload = null
    }

    return request
  }
}

class MemberRequest {
  constructor (discoveryKey, inviteId, requestData) {
    this.discoveryKey = discoveryKey
    this.id = inviteId
    this.requestData = requestData

    this._opened = false
    this._confirmed = false
    this._denied = false

    // set in open
    this.publicKey = null
    this.userData = null
    this.token = null
    this.receipt = null

    // set in confirm/respond
    this._payload = null
    this.response = null
  }

  static from (req) {
    if (b4a.isBuffer(req)) {
      return MemberRequest.from(c.decode(InviteRequest, req))
    }

    return new MemberRequest(
      req.discoveryKey,
      req.id,
      req.payload
    )
  }

  confirm (response) {
    if (this._confirmed || this._denied || !this._opened) return
    this._confirmed = true

    const payload = c.encode(ResponsePayload, response)
    this._payload = createReply(payload, this.token, this.publicKey)

    this._respond()
  }

  deny () {
    if (this._confirmed || this._denied) return
    this._denied = true
  }

  respond () {
    return {
      discoveryKey: this.discoveryKey,
      id: this.id,
      payload: this._confirmed ? this._payload : null
    }
  }

  _respond () {
    this.response = c.encode(InviteResponse, this.respond())
  }

  open (publicKey) {
    if (this._opened && b4a.equals(this.publicKey, publicKey)) return this.userData

    const requestData = this.requestData

    try {
      const { userData, token } = openAuth(requestData, publicKey)
      this.userData = userData
      this.token = token
    } catch (e) {
      throw new Error('Failed to open invite with provided key')
    }

    this.publicKey = publicKey
    this.receipt = c.encode(RequestPayload, requestData)
    this._opened = true

    return this.userData
  }
}

module.exports.CandidateRequest = CandidateRequest
module.exports.MemberRequest = MemberRequest
module.exports.createInvite = createInvite

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
    publicKey: keyPair.publicKey,
    discoveryKey
  }
}

function getKeyPair (seed) {
  const publicKey = b4a.allocUnsafe(sodium.crypto_sign_PUBLICKEYBYTES)
  const secretKey = b4a.allocUnsafe(sodium.crypto_sign_SECRETKEYBYTES)

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
