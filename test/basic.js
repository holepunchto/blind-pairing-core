const { once } = require('events')
const test = require('brittle')
const b4a = require('b4a')

const { CandidateRequest, MemberRequest, createInvite, verifyReceipt, createReceipt } = require('..')

test('basic valid pairing', async t => {
  const key = b4a.allocUnsafe(32).fill(1)

  const { invite, publicKey } = createInvite(key)

  const candidate = new CandidateRequest(invite, b4a.from('hello world'))
  const member = MemberRequest.from(candidate.encode())

  t.alike(member.inviteId, candidate.inviteId)

  const userData = member.open(publicKey)
  t.alike(userData, b4a.from('hello world'))
  t.alike(member.id, candidate.id)

  member.confirm({ key })

  const replied = once(candidate, 'accepted')

  candidate.handleResponse(member.response)
  const [reply] = await replied

  t.alike(reply.key, key)
})

test('basic receipt validation', async t => {
  t.plan(2)

  const key = b4a.allocUnsafe(32).fill(1)

  const { invite, publicKey } = createInvite(key)

  const candidate = new CandidateRequest(invite, b4a.from('hello world'))
  const member = MemberRequest.from(candidate.encode())
  member.open(publicKey)

  t.alike(verifyReceipt(member.receipt, publicKey), b4a.from('hello world'))
  t.alike(verifyReceipt(member.receipt.fill(0), publicKey), null)
})

test('create receipt', t => {
  const key = b4a.allocUnsafe(32).fill(1)
  const { invite, publicKey } = createInvite(key)
  const { receipt } = createReceipt(invite, Buffer.from('hello'))
  t.alike(verifyReceipt(receipt, publicKey), Buffer.from('hello'))
})

test('basic valid pairing with encryption key', async t => {
  t.plan(4)

  const key = b4a.allocUnsafe(32).fill(1)
  const encryptionKey = b4a.allocUnsafe(32).fill(2)

  const { invite, publicKey } = createInvite(key)

  const candidate = new CandidateRequest(invite, b4a.from('hello world'))
  const member = MemberRequest.from(candidate.encode())

  t.alike(member.inviteId, candidate.inviteId)

  const userData = member.open(publicKey)
  t.alike(userData, b4a.from('hello world'))
  t.alike(member.id, candidate.id)

  member.confirm({ key, encryptionKey })

  const replied = once(candidate, 'accepted')

  candidate.handleResponse(member.response)
  const [reply] = await replied

  t.alike(reply, { key, encryptionKey, data: null })
})

test('basic valid pairing with encryption key and data', async t => {
  t.plan(4)

  const key = b4a.allocUnsafe(32).fill(1)
  const encryptionKey = b4a.allocUnsafe(32).fill(2)
  const data = b4a.allocUnsafe(32).fill(3)

  const { invite, publicKey, additional } = createInvite(key, { data })

  const candidate = new CandidateRequest(invite, b4a.from('hello world'))
  const member = MemberRequest.from(candidate.encode())

  t.alike(member.inviteId, candidate.inviteId)

  const userData = member.open(publicKey)
  t.alike(userData, b4a.from('hello world'))
  t.alike(member.id, candidate.id)

  member.confirm({ key, encryptionKey, additional })

  const replied = once(candidate, 'accepted')

  candidate.handleResponse(member.response)
  const [reply] = await replied

  t.alike(reply, { key, encryptionKey, data })
})

test('does not leak invitee key to unproven inviters', async t => {
  t.plan(2)

  const key = b4a.allocUnsafe(32).fill(1)
  const { invite } = createInvite(key)

  const badKey = b4a.allocUnsafe(32).fill(2)

  const req = new CandidateRequest(invite, b4a.from('hello world'))

  const res = MemberRequest.from(req.encode())
  t.exception(() => res.open(badKey))

  t.alike(res.userData, null)
})

test('invite response is static', async t => {
  t.plan(12)

  const key = b4a.allocUnsafe(32).fill(1)
  const encryptionKey = b4a.allocUnsafe(32).fill(2)

  const invite = createInvite(key)
  const invite2 = createInvite(key)

  t.unlike(invite, invite2)

  const req1 = new CandidateRequest(invite.invite, b4a.from('hello world'))
  const req2 = new CandidateRequest(invite.invite, b4a.from('different'))
  const req3 = new CandidateRequest(invite2.invite, b4a.from('hello world'))

  t.unlike(req2.seed, req3.seed)

  t.unlike(req2.id, req1.id)
  t.unlike(req3.id, req1.id)
  t.unlike(req3.id, req2.id)

  const res1 = MemberRequest.from(req1)
  const res2 = MemberRequest.from(req2)
  const res3 = MemberRequest.from(req3)

  res1.open(invite.publicKey)
  res2.open(invite.publicKey)
  res3.open(invite2.publicKey)

  t.unlike(res2.receipt, res1.receipt)
  t.unlike(res3.receipt, res1.receipt)

  res1.confirm({ key, encryptionKey })
  res2.confirm({ key, encryptionKey })
  res3.confirm({ key, encryptionKey })

  t.unlike(res2.response, res1.response)
  t.unlike(res3.response, res1.response)

  const promise1 = new Promise(resolve => req1.on('accepted', resolve))
  const promise2 = new Promise(resolve => req2.on('accepted', resolve))
  const promise3 = new Promise(resolve => req3.on('accepted', resolve))

  req1.handleResponse(res1.response)
  req2.handleResponse(res2.response)
  req3.handleResponse(res3.response)

  t.alike(await promise1, { key, encryptionKey, data: null })
  t.alike(await promise2, { key, encryptionKey, data: null })
  t.alike(await promise3, { key, encryptionKey, data: null })
})

test('using a request - response', async t => {
  t.plan(2)

  const key = b4a.allocUnsafe(32).fill(1)

  const { invite, publicKey } = createInvite(key)

  const req = new CandidateRequest(invite, b4a.from('hello world'))
  const res = MemberRequest.from(req.encode())

  const userData = res.open(publicKey)
  t.alike(userData, b4a.from('hello world'))

  res.confirm({ key })

  const accept = once(req, 'accepted')
  req.handleResponse(res.response)

  const [reply] = await accept
  t.alike(reply.key, key)
})

test('restoring a request', async t => {
  t.plan(2)

  const key = b4a.allocUnsafe(32).fill(1)

  const { invite, publicKey } = createInvite(key)

  const req = new CandidateRequest(invite, b4a.from('hello world'))
  const res = MemberRequest.from(req.encode())

  const userData = res.open(publicKey)
  t.alike(userData, b4a.from('hello world'))

  res.confirm({ key })

  const req2 = new CandidateRequest(invite, b4a.from('hello world'))

  req2.on('rejected', err => t.fail(err))

  const accept = once(req2, 'accepted')
  req2.handleResponse(res.response)

  const [reply] = await accept
  t.alike(reply.key, key)
})

test('pass session token', async t => {
  t.plan(4)

  const key = b4a.allocUnsafe(32).fill(1)
  const session = b4a.allocUnsafe(32).fill(0xff)

  const { invite, publicKey } = createInvite(key)

  const candidate = new CandidateRequest(invite, b4a.from('hello world'), { session })

  t.alike(candidate.session, session)

  const replied = once(candidate, 'accepted')

  const member = MemberRequest.from(candidate.encode())
  const userData = member.open(publicKey)

  t.alike(userData, b4a.from('hello world'))
  t.alike(member.session, session)

  member.confirm({ key })

  candidate.handleResponse(member.response)
  const [reply] = await replied

  t.alike(reply.key, key)
})

test('deny request', async t => {
  t.plan(2)

  const key = b4a.allocUnsafe(32).fill(1)
  const session = b4a.allocUnsafe(32).fill(0xff)

  const { invite, publicKey } = createInvite(key)

  const candidate = new CandidateRequest(invite, b4a.from('hello world'), { session })

  const member = MemberRequest.from(candidate.encode())
  member.open(publicKey)

  member.deny({ status: 1 })

  const rejected = once(candidate, 'rejected')
  candidate.handleResponse(member.response)

  const [err] = await rejected

  t.alike(err.code, 'PAIRING_REJECTED')
  t.alike(candidate.auth, null)
})

test('candidate accepted after deny', async t => {
  t.plan(3)

  const key = b4a.allocUnsafe(32).fill(1)
  const session = b4a.allocUnsafe(32).fill(0xff)

  const { invite, publicKey } = createInvite(key)

  const candidate = new CandidateRequest(invite, b4a.from('hello world'), { session })

  const member = MemberRequest.from(candidate.encode())
  member.open(publicKey)
  member.deny({ status: 1 })

  const rejected = once(candidate, 'rejected')
  candidate.handleResponse(member.response)

  await rejected

  t.alike(candidate.auth, null)

  const member2 = MemberRequest.from(candidate.encode())
  member2.open(publicKey)
  member2.confirm({ key })

  const accepted = once(candidate, 'accepted')
  candidate.handleResponse(member2.response)

  await t.execution(accepted)

  t.alike(candidate.auth, { key, encryptionKey: null, data: null })
})
