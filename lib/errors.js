module.exports = class PairingError extends Error {
  constructor (msg, code, fn = PairingError) {
    super(`${code}: ${msg}`)
    this.code = code

    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, fn)
    }
  }

  get name () {
    return 'PairingError'
  }

  static PAIRING_REJECTED (msg = 'Pairing was rejected') {
    return new PairingError(msg, 'PAIRING_REJECTED', PairingError.PAIRING_REJECTED)
  }

  static INVITE_USED (msg = 'Invite has been used') {
    return new PairingError(msg, 'INVITE_USED', PairingError.INVITE_USED)
  }

  static INVITE_EXPIRED (msg = 'Invite has expireds') {
    return new PairingError(msg, 'INVITE_EXPIRED', PairingError.INVITE_EXPIRED)
  }
}
