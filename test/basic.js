const { once } = require('events')
const test = require('brittle')
const b4a = require('b4a')
const c = require('compact-encoding')

const { Invite } = require('../lib/messages')
const { CandidateRequest, MemberRequest, createInvite } = require('..')

test('basic valid pairing', async t => {
  t.plan(4)

  const key = b4a.allocUnsafe(32).fill(1)

  const { id, invite, publicKey } = createInvite(key)

  const candidate = new CandidateRequest(invite, b4a.from('hello world'))

  t.alike(candidate.id, id)

  const replied = once(candidate, 'accepted')

  const member = MemberRequest.from(candidate.encode())

  t.alike(member.id, id)

  const userData = member.open(publicKey)
  t.alike(userData, b4a.from('hello world'))

  member.confirm(key)

  candidate.handleResponse(member.response)
  const [reply] = await replied

  t.alike(reply, key)
})

test('basic invalid pairing', async t => {
  const key = b4a.allocUnsafe(32).fill(1)

  const { invite, publicKey } = createInvite(key)

  const decoded = c.decode(Invite, invite)
  decoded.seed = b4a.allocUnsafe(32).fill(1)
  const badInvite = c.encode(Invite, decoded)

  const candidate = new CandidateRequest(badInvite, b4a.from('hello world'))

  const member = MemberRequest.from(candidate.encode())
  const userData = member.open(publicKey)

  if (userData) t.fail()
  else t.pass()

  member.deny()

  const rejected = once(candidate, 'rejected')

  candidate.handleResponse(member.response)
  await t.execution(rejected)
})

test('does not leak invitee key to unproven inviters', async t => {
  t.plan(1)

  const key = b4a.allocUnsafe(32).fill(1)
  const { invite } = createInvite(key)

  const badKey = b4a.allocUnsafe(32).fill(2)

  const req = new CandidateRequest(invite, b4a.from('hello world'))

  const res = MemberRequest.from(req.encode())
  res.open(badKey)

  t.alike(res.userData, null)
})

test('invite response is static', async t => {
  t.plan(9)

  const key = b4a.allocUnsafe(32).fill(1)

  const invite = createInvite(key)
  const invite2 = createInvite(key)

  t.unlike(invite, invite2)

  const req1 = new CandidateRequest(invite.invite, b4a.from('hello world'))
  const req2 = new CandidateRequest(invite.invite, b4a.from('different'))
  const req3 = new CandidateRequest(invite2.invite, b4a.from('hello world'))

  t.unlike(req2.seed, req3.seed)

  const res1 = MemberRequest.from(req1)
  const res2 = MemberRequest.from(req2)
  const res3 = MemberRequest.from(req3)

  res1.open(invite.publicKey)
  res2.open(invite.publicKey)
  res3.open(invite2.publicKey)

  t.unlike(res2.receipt, res1.receipt)
  t.unlike(res3.receipt, res1.receipt)

  res1.confirm(key)
  res2.confirm(key)
  res3.confirm(key)

  t.unlike(res2.response, res1.response)
  t.unlike(res3.response, res1.response)

  const promise1 = new Promise(resolve => req1.on('accepted', resolve))
  const promise2 = new Promise(resolve => req2.on('accepted', resolve))
  const promise3 = new Promise(resolve => req3.on('accepted', resolve))

  req1.handleResponse(res1.response)
  req2.handleResponse(res2.response)
  req3.handleResponse(res3.response)

  t.alike(await promise1, key)
  t.alike(await promise2, key)
  t.alike(await promise3, key)
})

test('using a request - payload', async t => {
  t.plan(2)

  const key = b4a.allocUnsafe(32).fill(1)

  const { invite, publicKey } = createInvite(key)

  const req = new CandidateRequest(invite, b4a.from('hello world'))
  const res = MemberRequest.from(req.encode())

  const userData = res.open(publicKey)
  t.alike(userData, b4a.from('hello world'))

  res.confirm(key)

  const accept = once(req, 'accepted')
  req.handleResponse(res.respond().payload)

  const [reply] = await accept
  t.alike(reply, key)
})

test('using a request - response', async t => {
  t.plan(2)

  const key = b4a.allocUnsafe(32).fill(1)

  const { invite, publicKey } = createInvite(key)

  const req = new CandidateRequest(invite, b4a.from('hello world'))
  const res = MemberRequest.from(req.encode())

  const userData = res.open(publicKey)
  t.alike(userData, b4a.from('hello world'))

  res.confirm(key)

  const accept = once(req, 'accepted')
  req.handleResponse(res.response)

  const [reply] = await accept
  t.alike(reply, key)
})

test('restoring a request', async t => {
  t.plan(2)

  const key = b4a.allocUnsafe(32).fill(1)

  const { invite, publicKey } = createInvite(key)

  const req = new CandidateRequest(invite, b4a.from('hello world'))
  const stored = req.persist()

  const res = MemberRequest.from(req.encode())

  const userData = res.open(publicKey)
  t.alike(userData, b4a.from('hello world'))

  res.confirm(key)

  const req2 = CandidateRequest.from(stored)

  req2.on('rejected', err => t.fail(err))

  const accept = once(req2, 'accepted')
  req2.handleResponse(res.response)

  const [reply] = await accept
  t.alike(reply, key)
})
