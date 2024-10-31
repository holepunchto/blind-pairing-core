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

### `req.id`

Unique id for this request.

### `req.inviteId`

Invite id corresponding to this request.

### `req.discoveryKey`

Discovery key corresponding to this request.

#### `req.on('accepted', key => { ... })`

An event that fires when an invite is accepted.

#### `req.on('rejected', err => { ... })`

An event that fires when an invite is rejected.

#### `const persisted = req.persist()`

Returns a buffer that can be used to restore the request at a later point.

#### `CandidateRequest.from (persisted)`

Restore a persisted request.

### `MemberRequest` API

#### `const req = new MemberRequest(inviteId, requestData)`

Instantiate a new member request using the request id and the request data

#### `const userData = req.open(invitePublicKey)`

Open the request using the corresponding invitation public key.

#### `req.confirm({ key, encryptionKey })`

Confirm the request with the requested auth data.

#### `req.deny()`

Deny the request.

#### `const req = MemberRequest.from(incomingRequest)`

Static method to create a member request directly from a received request.

#### `req.inviteId`

The invite id corresponding to the request, this can be used to find the invitation public key.

#### `req.id`

The unique id corresponding to the request.

#### `req.response`

The response that should be sent back to the candidate. Only populated after the request is either confirmed or denied.

#### `req.receipt`

A stand alone receipt of this request that can be verified against the public key.

### `req.discoveryKey`

Discovery key corresponding to this request.

### `const { invite, discoveryKey, publicKey } = createInvite(key)`

Create invites for a given key.

### `const { discoveryKey, seed } = decodeInvite(invite)`

Decode an `invite` object.

### `const userData = verifyReceipt(receipt, invitePublicKey)`

Verify a previously opened request. Returns `userData` if receipt is valid and `null` otherwise.

## License

Apache-2.0
