const c = require('compact-encoding')
const b4a = require('b4a')

const ZERO = b4a.alloc(0)

const Invite = {
  preencode (state, i) {
    state.end++ // reserved
    c.fixed32.preencode(state, i.discoveryKey)
    c.fixed32.preencode(state, i.seed)
  },
  encode (state, i) {
    state.start++ // reserved
    c.fixed32.encode(state, i.discoveryKey)
    c.fixed32.encode(state, i.seed)
  },
  decode (state) {
    state.start++ // reserved
    return {
      discoveryKey: c.fixed32.decode(state),
      seed: c.fixed32.decode(state)
    }
  }
}

const RequestPayload = {
  preencode (state, p) {
    c.buffer.preencode(state, p.token)
    c.buffer.preencode(state, p.data)
  },
  encode (state, p) {
    c.buffer.encode(state, p.token)
    c.buffer.encode(state, p.data)
  },
  decode (state) {
    return {
      token: c.buffer.decode(state),
      data: c.buffer.decode(state)
    }
  }
}

const ResponsePayload = {
  preencode (state, p) {
    c.fixed32.preencode(state, p.key)
    state.end++ //flag
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
    const flag = c.uint.decode(state)
    const encryptionKey = flag ? c.fixed32.decode(state) : null

    return {
      key,
      encryptionKey
    }
  }
}

const InviteRequest = {
  preencode (state, i) {
    c.fixed32.preencode(state, i.discoveryKey)
    c.fixed32.preencode(state, i.id)
    RequestPayload.preencode(state, i.payload)
  },
  encode (state, i) {
    c.fixed32.encode(state, i.discoveryKey)
    c.fixed32.encode(state, i.id)
    RequestPayload.encode(state, i.payload)
  },
  decode (state) {
    return {
      discoveryKey: c.fixed32.decode(state),
      id: c.fixed32.decode(state),
      payload: RequestPayload.decode(state)
    }
  }
}

const InviteResponse = {
  preencode (state, i) {
    c.fixed32.preencode(state, i.discoveryKey)
    c.fixed32.preencode(state, i.id)
    c.buffer.preencode(state, i.payload)
  },
  encode (state, i) {
    c.fixed32.encode(state, i.discoveryKey)
    c.fixed32.encode(state, i.id)
    c.buffer.encode(state, i.payload)
  },
  decode (state) {
    return {
      discoveryKey: c.fixed32.decode(state),
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
    c.buffer.preencode(state, i.token)
    c.buffer.preencode(state, i.userData)
  },
  encode (state, i) {
    c.buffer.encode(state, i.token)
    c.buffer.encode(state, i.userData)
  },
  decode (state) {
    return {
      token: c.buffer.decode(state),
      userData: c.buffer.decode(state)
    }
  }
}

module.exports = {
  Invite,
  RequestPayload,
  ResponsePayload,
  InviteRequest,
  InviteResponse,
  InviteData,
  PersistedRequest,
  AuthData
}
