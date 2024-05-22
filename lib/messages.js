const c = require('compact-encoding')

const Invite = {
  preencode (state, i) {
    state.end++ // version
    state.end++ // flags
    c.fixed32.preencode(state, i.seed)
    if (i.discoveryKey) c.fixed32.preencode(state, i.discoveryKey)
    if (i.expires) c.uint32.preencode(state, Math.floor(i.expires / 1000)) // store as secs
  },
  encode (state, i) {
    c.uint.encode(state, 1) // version
    c.uint.encode(state, (i.discoveryKey ? 1 : 0) | (i.expires ? 2 : 0) | (i.sensitive ? 4 : 0) | (i.testInvitation ? 8 : 0))
    c.fixed32.encode(state, i.seed)
    if (i.discoveryKey) c.fixed32.encode(state, i.discoveryKey)
    if (i.expires) c.uint32.encode(state, Math.floor(i.expires / 1000))
  },
  decode (state) {
    const version = c.uint.decode(state)
    if (version !== 1) {
      throw new Error('Unknown invite version')
    }

    const flags = c.uint.decode(state)

    return {
      seed: c.fixed32.decode(state),
      discoveryKey: (flags & 1) ? c.fixed32.decode(state) : null,
      expires: (flags & 2) ? c.uint32.decode(state) * 1000 : 0,
      sensitive: (flags & 4) !== 0,
      testInvitation: (flags & 8) !== 0
    }
  }
}

const RequestPayload = {
  preencode (state, p) {
    c.buffer.preencode(state, p.session)
    c.buffer.preencode(state, p.data)
  },
  encode (state, p) {
    c.buffer.encode(state, p.session)
    c.buffer.encode(state, p.data)
  },
  decode (state) {
    return {
      session: c.buffer.decode(state),
      data: c.buffer.decode(state)
    }
  }
}

const ResponseStatus = c.uint

const AdditionalData = {
  preencode (state, m) {
    c.buffer.preencode(state, m.data)
    c.fixed64.preencode(state, m.signature)
  },
  encode (state, m) {
    c.buffer.encode(state, m.data)
    c.fixed64.encode(state, m.signature)
  },
  decode (state) {
    return {
      data: c.buffer.decode(state),
      signature: c.fixed64.decode(state)
    }
  }
}

const ResponsePayload = {
  preencode (state, p) {
    ResponseStatus.preencode(state, p.status)
    if (p.status !== 0) return

    let flags = 0
    if (p.encryptionKey) flags |= 1
    if (p.additional) flags |= 2
    c.uint.preencode(state, flags) // flags

    c.fixed32.preencode(state, p.key)
    if (p.encryptionKey) c.fixed32.preencode(state, p.encryptionKey)
    if (p.additional) AdditionalData.preencode(state, p.additional)
  },
  encode (state, p) {
    ResponseStatus.encode(state, p.status)
    if (p.status !== 0) return

    let flags = 0
    if (p.encryptionKey) flags |= 1
    if (p.additional) flags |= 2
    c.uint.encode(state, flags)

    c.fixed32.encode(state, p.key)
    if (p.encryptionKey) c.fixed32.encode(state, p.encryptionKey)
    if (p.additional) AdditionalData.encode(state, p.additional)
  },
  decode (state) {
    const status = ResponseStatus.decode(state)

    if (status !== 0) {
      return {
        status,
        key: null,
        encryptionKey: null,
        additional: null
      }
    }

    const flags = c.uint.decode(state)
    const key = c.fixed32.decode(state)
    const encryptionKey = (flags & 1) !== 0 ? c.fixed32.decode(state) : null
    const additional = (flags & 2) !== 0 ? AdditionalData.decode(state) : null

    return {
      status: 0,
      key,
      encryptionKey,
      additional
    }
  }
}

const InviteRequest = {
  preencode (state, i) {
    c.fixed32.preencode(state, i.inviteId)
    RequestPayload.preencode(state, i.payload)
  },
  encode (state, i) {
    c.fixed32.encode(state, i.inviteId)
    RequestPayload.encode(state, i.payload)
  },
  decode (state) {
    return {
      inviteId: c.fixed32.decode(state),
      payload: RequestPayload.decode(state)
    }
  }
}

const InviteResponse = {
  preencode (state, i) {
    c.fixed32.preencode(state, i.id)
    c.buffer.preencode(state, i.payload)
  },
  encode (state, i) {
    c.fixed32.encode(state, i.id)
    c.buffer.encode(state, i.payload)
  },
  decode (state) {
    return {
      id: c.fixed32.decode(state),
      payload: c.buffer.decode(state)
    }
  }
}

const InviteData = {
  preencode (state, i) {
    c.fixed64.preencode(state, i.signature)
    c.buffer.preencode(state, i.userData)
  },
  encode (state, i) {
    c.fixed64.encode(state, i.signature)
    c.buffer.encode(state, i.userData)
  },
  decode (state) {
    return {
      signature: c.fixed64.decode(state),
      userData: c.buffer.decode(state)
    }
  }
}

const InviteReceipt = {
  preencode (state, i) {
    c.fixed32.preencode(state, i.session)
    c.fixed64.preencode(state, i.signature)
    c.buffer.preencode(state, i.userData)
  },
  encode (state, i) {
    c.fixed32.encode(state, i.session)
    c.fixed64.encode(state, i.signature)
    c.buffer.encode(state, i.userData)
  },
  decode (state) {
    return {
      session: c.fixed32.decode(state),
      signature: c.fixed64.decode(state),
      userData: c.buffer.decode(state)
    }
  }
}

const AuthData = {
  preencode (state, i) {
    c.buffer.preencode(state, i.session)
    c.buffer.preencode(state, i.userData)
  },
  encode (state, i) {
    c.buffer.encode(state, i.session)
    c.buffer.encode(state, i.userData)
  },
  decode (state) {
    return {
      session: c.buffer.decode(state),
      userData: c.buffer.decode(state)
    }
  }
}

module.exports = {
  Invite,
  ResponsePayload,
  InviteRequest,
  InviteResponse,
  InviteData,
  InviteReceipt,
  AuthData
}
