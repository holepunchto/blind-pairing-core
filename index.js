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

const {
  PAIRING_REJECTED,
  INVITE_USED,
  INVITE_EXPIRED
} = require('./lib/errors')

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
      this.response = c.decode(ResponsePayload, response)
    } catch (e) {
      throw new Error('Could not decrypt reply.')
    }

    const { status, key, encryptionKey, additional } = this.response

    if (status !== 0) {
      switch (status) {
        case 1:
          throw PAIRING_REJECTED()

        case 2:
          throw INVITE_USED()

        case 3:
          throw INVITE_EXPIRED()
      }
    }

    if (b4a.compare(crypto.discoveryKey(key), this.discoveryKey)) {
      throw new Error('Invite response does not match discoveryKey')
    }

    if (additional && !crypto.verify(additional.data, additional.signature, this.keyPair.publicKey)) {
      throw new Error('Additional data failed verification')
    }

    this.auth = { key, encryptionKey, data: additional ? additional.data : null }
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

  confirm ({ key, encryptionKey, additional }) {
    if (this._confirmed || this._denied || !this._opened) return
    this._confirmed = true

    const payload = c.encode(ResponsePayload, { status: 0, key, encryptionKey, additional })
    this._payload = createReply(payload, this.session, this.publicKey)

    this._respond()
  }

  deny ({ status = 1 } = {}) {
    if (this._confirmed || this._denied) return
    this._denied = true

    if (!status) return

    const payload = c.encode(ResponsePayload, {
      status,
      key: null,
      encryptionKey: null,
      additional: null
    })
    this._payload = createReply(payload, this.session, this.publicKey)

    this._respond()
  }

  respond () {
    return {
      id: this.id,
      payload: this._payload
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
module.exports.Invite = Invite

function verifyReceipt (receipt, publicKey) {
  if (b4a.isBuffer(receipt)) {
    receipt = c.decode(InviteReceipt, receipt)
  }

  const { session, signature, userData } = receipt
  const signData = c.encode(AuthData, { userData, session })

  if (!verifySignature(signData, signature, publicKey)) return null

  return userData
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

function createInvite (key, opts = {}) {
  const {
    discoveryKey = crypto.discoveryKey(key),
    expires = 0,
    seed = crypto.randomBytes(32),
    sensitive = false,
    data,
    testInvitation = false
  } = opts

  const keyPair = crypto.keyPair(seed)
  const additional = data
    ? {
        data,
        signature: crypto.sign(data, keyPair.secretKey)
      }
    : null

  return {
    id: deriveInviteId(keyPair.publicKey),
    invite: c.encode(Invite, { seed, discoveryKey, expires, sensitive, testInvitation }),
    publicKey: keyPair.publicKey,
    additional,
    discoveryKey,
    expires,
    sensitive,
    testInvitation
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
