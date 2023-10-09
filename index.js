const { EventEmitter } = require('events')
const sodium = require('sodium-universal')
const crypto = require('hypercore-crypto')
const b4a = require('b4a')
const c = require('compact-encoding')

const {
  Invite,
  ResponsePayload,
  InviteRequest,
  InviteResponse,
  InviteData,
  InviteReceipt,
  PersistedRequest,
  AuthData
} = require('./lib/messages')

const [
  NS_SIGNATURE,
  NS_TOKEN,
  NS_INVITE_ID,
  NS_REQUEST_ID,
  NS_SESSION,
  NS_SESSION_KEY,
  NS_ENCRYPT,
  NS_NONCE
] = crypto.namespace('blind-pairing', 8)

class CandidateRequest extends EventEmitter {
  constructor (invite, userData, opts = {}) {
    super()

    if (b4a.isBuffer(invite)) {
      invite = c.decode(Invite, invite)
    }

    this.discoveryKey = invite.discoveryKey
    this.seed = invite.seed

    this.keyPair = crypto.keyPair(this.seed)
    this.inviteId = deriveInviteId(this.keyPair.publicKey)
    this.userData = userData

    this.token = deriveToken(this.keyPair.publicKey, userData)
    this.session = opts.session || createSessionToken(this.token)
    this.id = deriveRequestId(this.session)

    this.payload = createAuth(this.userData, this.keyPair, this.session)

    this._encoded = null

    // set in reply
    this.auth = null
  }

  static from (buf) {
    const info = c.decode(PersistedRequest, buf)
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

  handleResponse (payload) {
    if (b4a.isBuffer(payload)) {
      payload = this._decodeResponse(payload)
    }

    try {
      this._openResponse(payload)
    } catch (err) {
      this.emit('rejected', err)
      return null
    }

    this._onAccept()

    return this.auth
  }

  _openResponse (payload) {
    try {
      const response = openReply(payload, this.payload.session, this.keyPair.publicKey)
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
    if (!this._encoded) this._encoded = c.encode(InviteRequest, this)
    return this._encoded
  }

  persist () {
    return c.encode(PersistedRequest, this)
  }
}

class MemberRequest {
  constructor (inviteId, requestData) {
    this.inviteId = inviteId
    this.requestData = requestData

    this._opened = false
    this._confirmed = false
    this._denied = false

    // set by transport
    this.discoveryKey = null

    // set in open
    this.publicKey = null
    this.userData = null
    this.session = null
    this.id = null
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
      req.inviteId,
      req.payload
    )
  }

  confirm (response) {
    if (this._confirmed || this._denied || !this._opened) return
    this._confirmed = true

    const payload = c.encode(ResponsePayload, response)
    this._payload = createReply(payload, this.session, this.publicKey)

    this._respond()
  }

  deny () {
    if (this._confirmed || this._denied) return
    this._denied = true
  }

  respond () {
    return {
      id: this.id,
      payload: this._confirmed ? this._payload : null
    }
  }

  _respond () {
    this.response = c.encode(InviteResponse, this.respond())
  }

  open (publicKey) {
    if (this._opened && b4a.equals(this.publicKey, publicKey)) return this.userData

    try {
      this.receipt = openAuth(this.requestData, publicKey)
      const { userData, session } = c.decode(InviteReceipt, this.receipt)

      this.userData = userData
      this.session = session
      this.token = deriveToken(publicKey, userData)
      this.id = deriveRequestId(this.session)
    } catch (e) {
      throw new Error('Failed to open invite with provided key')
    }

    this.publicKey = publicKey
    this._opened = true

    return this.userData
  }
}

module.exports.CandidateRequest = CandidateRequest
module.exports.MemberRequest = MemberRequest
module.exports.createInvite = createInvite
module.exports.decodeInvite = decodeInvite
module.exports.verifyReceipt = verifyReceipt

function verifyReceipt (receipt, publicKey) {
  if (b4a.isBuffer(receipt)) {
    receipt = c.decode(InviteReceipt, receipt)
  }

  const { session, signature, userData } = receipt
  const signData = c.encode(AuthData, { userData, session })

  return verifySignature(signData, signature, publicKey)
}

function deriveInviteId (publicKey) {
  return crypto.hash([NS_INVITE_ID, publicKey])
}

function deriveKey (publicKey) {
  const out = b4a.allocUnsafe(sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES)
  return crypto.hash([NS_ENCRYPT, publicKey], out)
}

function deriveNonce (publicKey, sessionToken) {
  const out = b4a.allocUnsafe(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES)
  return crypto.hash([NS_NONCE, publicKey, sessionToken], out)
}

function deriveToken (publicKey, userData) {
  return crypto.hash([NS_TOKEN, publicKey, userData])
}

function createSessionToken (token) {
  return crypto.hash([NS_SESSION, token])
}

function deriveRequestId (sessionToken) {
  return crypto.hash([NS_REQUEST_ID, sessionToken])
}

function createInvite (key) {
  const discoveryKey = crypto.discoveryKey(key)
  const seed = crypto.randomBytes(32)
  const keyPair = crypto.keyPair(seed)

  return {
    id: deriveInviteId(keyPair.publicKey),
    invite: c.encode(Invite, { discoveryKey, seed }),
    publicKey: keyPair.publicKey,
    discoveryKey
  }
}

function decodeInvite (invite) {
  return c.decode(Invite, invite)
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

function createAuth (userData, invitationKeyPair, session) {
  const secret = deriveKey(invitationKeyPair.publicKey)

  const nonce = deriveNonce(invitationKeyPair.publicKey, session)
  const signData = c.encode(AuthData, { userData, session })
  const signature = createSignature(signData, invitationKeyPair.secretKey)

  const inviteData = c.encode(InviteData, { userData, signature })
  const data = encrypt(inviteData, nonce, secret)

  return {
    session,
    data
  }
}

function openAuth (payload, invitationKey) {
  const secret = deriveKey(invitationKey)

  const { session, data } = payload

  const nonce = deriveNonce(invitationKey, session)

  let plaintext
  try {
    plaintext = decrypt(data, nonce, secret)
  } catch {
    // todo stronger check
    throw new Error('Decryption failed.')
  }

  const { userData, signature } = c.decode(InviteData, plaintext)
  const receipt = { session, signature, userData }

  if (!verifyReceipt(receipt, invitationKey)) {
    throw new Error('Invalid reply')
  }

  return c.encode(InviteReceipt, { session, signature, userData })
}

function createReply (payload, sessionToken, invitationKey) {
  const sessionKey = crypto.hash([NS_SESSION_KEY, invitationKey, sessionToken])
  const secret = deriveKey(sessionKey)
  const nonce = deriveNonce(sessionKey, sessionToken)

  return encrypt(payload, nonce, secret)
}

function openReply (data, sessionToken, invitationKey) {
  const sessionKey = crypto.hash([NS_SESSION_KEY, invitationKey, sessionToken])
  const secret = deriveKey(sessionKey)
  const nonce = deriveNonce(sessionKey, sessionToken)

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
