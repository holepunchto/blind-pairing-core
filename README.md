# blind-pairing-core

### Pairing Flow

The pairing flow proceeds as follows:
1. The member (inviter) creates an invitation (a new signing keypair) and shares `{ discoveryKey, seed }` with a candidate (invitee). `publicKey` is set aside for later use.
2. The candidate produces a request with arbitrary `userData` signed by the invitation keyPair, this is encrypted to a key derived from the invite `publicKey`.
3. Upon receiving the request, the member decrypts the payload and verifies the signature against the invitation `publicKey`, proving that the invitee has `secretKey`.
4. The member can evaluate `userData` and either confirm or deny the request. A response is returned to the candidate which may contain the `{ key, encryptionKey }` needed to join the room.
5. The candidate verifies that `key` corresponds to `discoveryKey`, confirming that the remote peer has read-access to `key` (is a valid member).

## Usage

```js
import { CandidateRequest, MemberRequest, createInvite } from 'blind-pairing-core'

const { invite, publicKey } = createInvite(key) // key is a Hypercore or Autobase key

// candidate

const candidate = new CandidateRequest(invite, { userData: 'hello world' })
candidate.on('accepted', () => console.log('accepted!'))

const transport = candidate.encode() 

// member

const request = MemberRequest.from(transport)

const userData = request.open(publicKey)
console.log(userData) // hello world

request.confirm({ key })

// candidate

candidate.handleResponse(request.response)
// candidate accepted event will fire

console.log(candidate.auth) // { key }
```

## API

exports:
```
{
  CandidateRequest,
  MemberRequest,
  createInvite,
  decodeInvite,
  verifyReceipt
}
```

### `CandidateRequest` API

#### `const req = new CandidateRequest(invite, userData, opts = { session })`

Instanstiate a new candidate request from a given invite.

#### `const auth = req.handleResponse(payload)`

Handle the response received from the peer.

#### `req.destroy()`

Destroy the request.

#### `const buf = req.encode()`

Encode the request to be sent to the peer.

#### `const persisted = req.persist()`

Returns a buffer that can be used to restore the request at a later point.

#### `CandidateRequest.from (persisted)`

Restore a persisted request.

### `MemberRequest` API

#### `const req = new MemberRequest(requestId, requestData)`

Instantiate a new member request using the request id and the request data

#### `const userData = req.open(invitePublicKey)`

Open the request using the corresponding invitation public key.

#### `req.confirm({ key, encryptionKey })`

Confirm the request with the requested auth data.

#### `req.deny()`

Deny the request.

#### `const req = MemberRequest.from(incomingRequest)`

Static method to create a member request directly from a received request.

#### `req.id`

The unique id corresponding to the request

#### `req.response`

The response that should be sent back to the candidate. Only populated after the request is either confirmed or denied.

#### `req.receipt`

A stand alone receipt of this request that can be verified against the public key.

### `const { invite, discoveryKey, publicKey } = createInvite(key)`

Create invites for a given key.

### `const { discoveryKey, seed } = decodeInvite(invite)`

Decode an `invite` object.

### `const valid = verifyReceipt(receipt, invitePublicKey)`

Verify a previously opened request.

#### `PairingCore.decodeInvite(encoded)`

Static method to decode invites.

#### `PairingCore.openRequest(request, publicKey)`

Static method for opening requests.

#### `const pairing = new PairingCore()`

Instantiate a new pairing manager.

#### `pairing.join(key)`

Accept requests for a given key.

#### `pairing.leave(key)`

Stop accepting requests for a given key.

#### `const req = pairing.pair(invite, { userData })`

Create a new pairing request responding to `invite`.

`req` is an encrypted message that can be distributed to members that can complete the pairing. `userData` will only be available to parties who are autohrised to accept the invite.

#### `const req = pairing.handleRequest(requestInfo)`

Returns a `PairingRequest` object to the caller based of the received `requestInfo`.

#### `pairing.handleResponse(response)`

Receive a response and fulfill any pairing requests if possible.

#### `for (const req of pairing.requests())`

Iterate over all open requests.

### PairingRequest API

#### `req.discoveryKey`
The discovery key of the request.

#### `req.publicKey`
The public key sent by the requester (can be compared with the correct public key).

#### `req.receipt`
A statically verifiable receipt of the pairing request (can be verified by third parties).

#### `req.userData`
Optional user data sent by the requester.

#### `const userData = req.open(publicKey)`
Verify that the request signature matches the known public key and decrypt the payload.

Protopair cannot do this automatically, because pairing servers might receive requests for unknown public keys.

`req.confirm` should only be called if req passes `req.verify(publicKey)`.

#### `req.confirm()`

If `req.publicKey` matches the `publicKey` generated by `createInvite` above, and any additional app logic also passes, then the invitation can be confirmed.

This will send `key` back to the requester.

#### `req.deny()`

Will reject the request without sending a response back to the requester.

### ClientRequest API

#### `req.discoveryKey`
The discovery key of the request.

#### `req.publicKey`
The public key sent by the requester (can be compared with the correct public key).

#### `req.userData`
Optional user data sent by the requester.

#### `req.signature`
Lazily set immediately before the request is sent. Verified by the server before emitting the request as valid.

#### `req.destroy()`

Destroy the request.

#### `req.on('accepted', key => { ... })`

An event that fires when an invite is accepted.

#### `req.on('rejected', err => { ... })`

An event that fires when an invite is rejected.

## License
MIT
