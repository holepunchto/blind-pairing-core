const { once } = require('events')
const test = require('brittle')
const b4a = require('b4a')
const c = require('compact-encoding')

const { Invite } = require('../lib/messages')
const { PairingRequest, KeetPairing } = require('..')

test('basic valid pairing', async t => {
  t.plan(6)

  const key = b4a.allocUnsafe(32).fill(1)

  const pair1 = new KeetPairing()
  const pair2 = new KeetPairing()

  const { id, invite, publicKey } = KeetPairing.createInvite(key)

  pair1.join(key)

  const req = pair2.pair(invite, { userData: b4a.from('hello world') })
  t.alike(req.id, id)

  const replied = once(req, 'accepted')

  const res = await pair1.handleRequest(req)
  t.alike(res.key, key)
  t.alike(res.id, id)

  const userData = res.open(publicKey)
  t.alike(userData, b4a.from('hello world'))

  t.alike(KeetPairing.openRequest(res.receipt, publicKey), userData)

  res.confirm()

  pair2.handleResponse(res.response)
  const [reply] = await replied

  t.alike(reply, key)
})

test('basic invalid pairing', async t => {
  const key = b4a.allocUnsafe(32).fill(1)

  const pair1 = new KeetPairing()
  const pair2 = new KeetPairing()

  const { invite, publicKey } = KeetPairing.createInvite(key)

  pair1.join(key)

  const decoded = KeetPairing.decodeInvite(invite)
  decoded.seed = b4a.allocUnsafe(32).fill(1)
  const badInvite = c.encode(Invite, decoded)

  const req = pair2.pair(badInvite, { userData: b4a.from('hello world') })

  const res = await pair1.handleRequest(req)
  const userData = res.open(publicKey)

  if (userData) t.fail()
  else t.pass()

  res.deny()

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

  pair1.join(key)

  const req = pair2.pair(invite, { userData: b4a.from('hello world') })
  const res = await pair1.handleRequest(req)

  t.alike(res.key, key)

  const userData = res.open(publicKey)
  t.alike(userData, b4a.from('hello world'))

  setTimeout(() => {
    res.confirm()
    pair2.handleResponse(res.response)
  }, 100)

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

  pair2._joinedKeysByDKey.set(req.discoveryKey, badKey)

  const res = pair2.handleRequest(req)
  res.open(badKey)

  t.alike(res.userData, null)
})

test('invite response is static', async t => {
  t.plan(7)

  const key = b4a.allocUnsafe(32).fill(1)

  const invite = KeetPairing.createInvite(key)
  const invite2 = KeetPairing.createInvite(key)

  t.unlike(invite, invite2)

  const p1 = new KeetPairing()
  const p2 = new KeetPairing()
  const p3 = new KeetPairing()

  p1.join(key)

  const req1 = p2.pair(invite.invite, { userData: b4a.from('hello world') })
  const req2 = p3.pair(invite.invite, { userData: b4a.from('hello world') })
  const req3 = p3.pair(invite2.invite, { userData: b4a.from('hello world') })

  t.unlike(req2.seed, req3.seed)

  const res1 = await p1.handleRequest(req1)
  const res2 = await p1.handleRequest(req2)
  const res3 = await p1.handleRequest(req3)

  res1.open(invite.publicKey)
  res2.open(invite.publicKey)
  res3.open(invite2.publicKey)

  t.alike(res2.payload, res1.payload)
  t.unlike(res3.payload, res1.payload)

  res1.confirm()
  res2.confirm()
  res3.confirm()

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

test('using a request - payload', async t => {
  t.plan(3)

  const key = b4a.allocUnsafe(32).fill(1)

  const pair = new KeetPairing()
  pair.join(key)

  const { invite, publicKey } = KeetPairing.createInvite(key)

  const req = KeetPairing.createRequest(invite, b4a.from('hello world'))
  const res = await pair.handleRequest(req)

  t.alike(res.key, key)

  const userData = res.open(publicKey)
  t.alike(userData, b4a.from('hello world'))

  res.confirm()

  const accept = once(req, 'accepted')
  req.handleResponse(res.respond().payload)

  const [reply] = await accept
  t.alike(reply, key)
})

test('using a request - response', async t => {
  t.plan(3)

  const key = b4a.allocUnsafe(32).fill(1)

  const pair = new KeetPairing()
  pair.join(key)

  const { invite, publicKey } = KeetPairing.createInvite(key)

  const req = KeetPairing.createRequest(invite, b4a.from('hello world'))
  const res = await pair.handleRequest(req)

  t.alike(res.key, key)

  const userData = res.open(publicKey)
  t.alike(userData, b4a.from('hello world'))

  res.confirm()

  const accept = once(req, 'accepted')
  req.handleResponse(res.response)

  const [reply] = await accept
  t.alike(reply, key)
})

test('restoring a request', async t => {
  t.plan(3)

  const key = b4a.allocUnsafe(32).fill(1)

  const pair = new KeetPairing()
  pair.join(key)

  const { invite, publicKey } = KeetPairing.createInvite(key)

  const req = KeetPairing.createRequest(invite, b4a.from('hello world'))
  const stored = req.persist()

  const res = await pair.handleRequest(req)

  t.alike(res.key, key)

  const userData = res.open(publicKey)
  t.alike(userData, b4a.from('hello world'))

  res.confirm()

  const req2 = PairingRequest.from(stored)

  req2.on('rejected', err => t.fail(err))

  const accept = once(req2, 'accepted')
  req2.handleResponse(res.response)

  const [reply] = await accept
  t.alike(reply, key)
})

test('adding a stored request', async t => {
  t.plan(3)

  const key = b4a.allocUnsafe(32).fill(1)

  const pair = new KeetPairing()
  const pair2 = new KeetPairing()

  pair.join(key)

  const { invite, publicKey } = KeetPairing.createInvite(key)

  const req = KeetPairing.createRequest(invite, b4a.from('hello world'))
  const stored = req.persist()

  const res = await pair.handleRequest(req)

  t.alike(res.key, key)

  const userData = res.open(publicKey)
  t.alike(userData, b4a.from('hello world'))

  res.confirm()

  const req2 = pair2.add(stored)

  const accept = once(req2, 'accepted')
  pair2.handleResponse(res.response)

  const [reply] = await accept
  t.alike(reply, key)
})
