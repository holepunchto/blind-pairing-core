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

const InvitePayload = {
  preencode (state, p) {
    if (p) {
      c.buffer.preencode(state, p.token)
      c.buffer.preencode(state, p.data)
    } else {
      c.buffer.preencode(state, ZERO)
    }
  },
  encode (state, p) {
    if (p) {
      c.buffer.encode(state, p.token)
      c.buffer.encode(state, p.data)
    } else {
      c.buffer.preencode(state, ZERO)
    }
  },
  decode (state) {
    const token = c.buffer.decode(state)
    if (!token) return null

    return {
      token,
      data: c.buffer.decode(state)
    }
  }
}

const InviteRequest = {
  preencode (state, i) {
    c.fixed32.preencode(state, i.discoveryKey)
    c.fixed32.preencode(state, i.id)
    InvitePayload.preencode(state, i.payload)
  },
  encode (state, i) {
    c.fixed32.encode(state, i.discoveryKey)
    c.fixed32.encode(state, i.id)
    InvitePayload.encode(state, i.payload)
  },
  decode (state) {
    return {
      discoveryKey: c.fixed32.decode(state),
      id: c.fixed32.decode(state),
      payload: InvitePayload.decode(state)
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

const PersistedRequest = {
  preencode (state, r) {
    c.fixed32.preencode(state, r.seed)
    c.fixed32.preencode(state, r.discoveryKey)
    c.buffer.preencode(state, r.userData)
    c.uint32.preencode(state, 0)
    for (const s of r.sessions.keys()) {
      c.fixed32.preencode(state, s)
    }
  },
  encode (state, r) {
    c.fixed32.encode(state, r.seed)
    c.fixed32.encode(state, r.discoveryKey)
    c.buffer.encode(state, r.userData)

    const prefix = state.start
    c.uint32.encode(state, 0)

    let len = 0
    for (const s of r.sessions.keys()) {
      len++
      c.fixed32.encode(state, s)
    }

    const end = state.start
    state.start = prefix
    c.uint32.encode(state, len)
    state.start = end
  },
  decode (state) {
    const req = {}

    req.seed = c.fixed32.decode(state)
    req.discoveryKey = c.fixed32.decode(state)
    req.userData = c.buffer.decode(state)

    req.sessions = []
    const len = c.uint32.decode(state)
    for (let i = 0; i < len; i++) {
      req.sessions.push(c.fixed32.decode(state))
    }

    return req
  }
}

module.exports = {
  Invite,
  InvitePayload,
  InviteRequest,
  InviteResponse,
  InviteData,
  AuthData,
  PersistedRequest
}
