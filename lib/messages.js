const c = require('compact-encoding')

const Invite = {
  preencode (state, i) {
    state.end++ // version
    state.end++ // flags
    c.fixed32.preencode(state, i.seed)
    if (i.discoveryKey) c.fixed32.preencode(state, i.discoveryKey)
    if (i.expires) c.uint32.preencode(state, i.expires)
  },
  encode (state, i) {
    c.uint.encode(state, 2) // version
    c.uint.encode(state, (i.discoveryKey ? 1 : 0) | (i.expires ? 2 : 0))
    c.fixed32.encode(state, i.seed)
    if (i.discoveryKey) c.fixed32.encode(state, i.discoveryKey)
    if (i.expires) c.uint32.encode(state, i.expires)
  },
  decode (state) {
    const version = c.uint.decode(state)
    if (version !== 2) {
      throw new Error('Unknown invite version')
    }

    const flags = c.uint.decode(state)

    return {
      seed: c.fixed32.decode(state),
      discoveryKey: (flags & 1) ? c.fixed32.decode(state) : null,
      expires: (flags & 2) ? c.uint32.decode(state) : 0
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

const ResponsePayload = {
  preencode (state, p) {
    c.fixed32.preencode(state, p.key)
    state.end++ // flags
    if (p.encryptionKey) {
      c.fixed32.preencode(state, p.encryptionKey)
    }
  },
  encode (state, p) {
    c.fixed32.encode(state, p.key)
    c.uint.encode(state, p.encryptionKey ? 1 : 0)
    if (p.encryptionKey) {
      c.fixed32.encode(state, p.encryptionKey)
    }
  },
  decode (state) {
    const key = c.fixed32.decode(state)
    const flags = c.uint.decode(state)
    const encryptionKey = flags & 1 ? c.fixed32.decode(state) : null

    return {
      key,
      encryptionKey
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

const PersistedRequest = {
  preencode (state, req) {
    c.fixed32.preencode(state, req.seed)
    c.fixed32.preencode(state, req.discoveryKey)
    c.buffer.preencode(state, req.userData)

    if (req.key) {
      c.uint8.preencode(state, 1)
      c.fixed32.preencode(state, req.key)
    } else {
      c.uint8.preencode(state, 0)
    }
  },
  encode (state, req) {
    c.fixed32.encode(state, req.seed)
    c.fixed32.encode(state, req.discoveryKey)
    c.buffer.encode(state, req.userData)

    if (req.key) {
      c.uint8.encode(state, 1)
      c.fixed32.encode(state, req.key)
    } else {
      c.uint8.encode(state, 0)
    }
  },
  decode (state, req) {
    const seed = c.fixed32.decode(state)
    const discoveryKey = c.fixed32.decode(state)
    const userData = c.buffer.decode(state)

    const key = c.uint8.decode(state)
      ? c.fixed32.decode(state)
      : null

    return {
      seed,
      discoveryKey,
      userData,
      key
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
  PersistedRequest,
  AuthData
}
