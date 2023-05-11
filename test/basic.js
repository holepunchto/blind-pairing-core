const { once } = require('events')
const test = require('brittle')
const b4a = require('b4a')
const c = require('compact-encoding')

const { Invite } = require('../lib/messages')
const { KeetPairing } = require('..')

test('basic valid pairing', async t => {
  t.plan(6)

  const key = b4a.allocUnsafe(32).fill(1)

  const pair1 = new KeetPairing()
  const pair2 = new KeetPairing()

  const { id, invite, publicKey } = KeetPairing.createInvite(key)

  pair1.join(key, req => {
    t.alike(req.key, key)
    t.alike(req.id, id)

    const userData = req.open(publicKey)
    t.alike(userData, b4a.from('hello world'))

    t.alike(KeetPairing.openRequest(req.receipt, publicKey), userData)

    req.confirm()
  })

  const req = pair2.pair(invite, { userData: b4a.from('hello world') })
  t.alike(req.id, id)

  const replied = once(req, 'accepted')

  const res = await pair1.handleRequest(req)

  pair2.handleResponse(res.response)
  const [reply] = await replied

  t.alike(reply, key)
})

test('basic invalid pairing', async t => {
  const key = b4a.allocUnsafe(32).fill(1)

  const pair1 = new KeetPairing()
  const pair2 = new KeetPairing()

  const { invite, publicKey } = KeetPairing.createInvite(key)

  pair1.join(key, req => {
    const userData = req.open(publicKey)

    if (userData) t.fail()
    else t.pass()

    req.deny()
  })

  const decoded = KeetPairing.decodeInvite(invite)
  decoded.seed = b4a.allocUnsafe(32).fill(1)
  const badInvite = c.encode(Invite, decoded)

  const req = pair2.pair(badInvite, { userData: b4a.from('hello world') })
  const res = await pair1.handleRequest(req)

  const rejected = once(req, 'rejected')

  pair2.handleResponse(res.response)
  await rejected
})

test('basic async confirmation', async t => {
  t.plan(3)

  const key = b4a.allocUnsafe(32).fill(1)

  const pair1 = new KeetPairing()
  const pair2 = new KeetPairing()

  const { invite, publicKey } = KeetPairing.createInvite(key)

  pair1.join(key, req => {
    t.alike(req.key, key)

    const userData = req.open(publicKey)
    t.alike(userData, b4a.from('hello world'))

    setTimeout(() => {
      req.confirm()
      pair2.handleResponse(res.response)
    }, 100)
  })

  const req = pair2.pair(invite, { userData: b4a.from('hello world') })
  const res = await pair1.handleRequest(req)

  const [reply] = await once(req, 'accepted')

  t.alike(reply, key)
})

test('does not leak invitee key to unproven inviters', async t => {
  t.plan(1)

  const key = b4a.allocUnsafe(32).fill(1)
  const { invite } = KeetPairing.createInvite(key)

  const badKey = b4a.allocUnsafe(32).fill(2)

  const pair1 = new KeetPairing()
  const pair2 = new KeetPairing()

  const req = pair1.pair(invite, { userData: b4a.from('hello world') })

  pair2._joinedKeysByDKey.set(req.discoveryKey, {
    key: badKey,
    onrequest (req) {
      t.alike(req.open(badKey), null)
    }
  })

  pair2.handleRequest(req)
})

test('invite response is static', async t => {
  t.plan(5)

  const key = b4a.allocUnsafe(32).fill(1)

  const invite = KeetPairing.createInvite(key)
  const invite2 = KeetPairing.createInvite(key)

  const p1 = new KeetPairing()
  const p2 = new KeetPairing()
  const p3 = new KeetPairing()

  let payload = null

  const onrequest = req => {
    if (!payload) {
      payload = req.payload
      req.open(invite.publicKey)
    } else if (b4a.compare(req.id, invite.id)) {
      t.unlike(payload, req.payload)
      req.open(invite2.publicKey)
    } else {
      t.alike(payload, req.payload)
      req.open(invite.publicKey)
    }

    try {
      req.confirm()
    } catch (e) {
      req.deny()
    }
  }

  p1.join(key, onrequest)

  const req1 = p2.pair(invite.invite, { userData: b4a.from('hello world') })
  const req2 = p3.pair(invite.invite, { userData: b4a.from('hello world') })
  const req3 = p3.pair(invite2.invite, { userData: b4a.from('hello world') })

  const res1 = await p1.handleRequest(req1)
  const res2 = await p1.handleRequest(req2)
  const res3 = await p1.handleRequest(req3)

  const promise1 = new Promise(resolve => req1.on('accepted', resolve))
  const promise2 = new Promise(resolve => req2.on('accepted', resolve))
  const promise3 = new Promise(resolve => req3.on('accepted', resolve))

  p2.handleResponse(res1.response)
  p3.handleResponse(res2.response)
  p3.handleResponse(res3.response)

  t.alike(await promise1, key)
  t.alike(await promise2, key)
  t.alike(await promise3, key)
})
