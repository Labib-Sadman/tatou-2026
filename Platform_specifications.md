# Platform specifications

 - Users SHOULD be able to upload documents on the platform.
 - Documents without watermarks MUST be accessible only to their owner (and the platform).
 - Users SHOULD be able to generate watermarked version of their documents.
 - Watermarks SHOULD be hard to remove.
 - Watermarks MUST allow secret retrieval by the owner of the document allowing the identification of the document's version.
 - The platform SHOULD be able to create a secret link to each watermarked document. The link SHOULD not be guessable by anyone else that the document owner (and the platform).
 - A watermarked document MAY be downloaded by anyone having knowledge of the link.
 - Original document metadata (name, size, numbers, internal ids, list of watermarked versions, etc) SHOULD be confidential (known only by the document's owner and the platform).
 - Documents SHOULD be available to their owner.
 - Documents SHOULD be removable by their owner.
 - Documents SHOULD not be modifiable by third parties.

 ### RMAP handshake

- The handshake MUST reject a previously used client or server nonce, and a
  session MUST be invalidated once it has been used to issue a link.

- Handshake state MUST be consistent across all server processes.

- Handshake attempts, including rejected ones, SHOULD be recorded.

### Watermarking

- A watermarking method MUST refuse a document it cannot carry a payload in,
  rather than producing a version whose secret cannot be recovered.

- The platform MUST retain the key material required to read back every
  watermark it has issued, for as long as attribution may be needed.
