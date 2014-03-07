-- |
-- Module      : Crypto.Encrypt.Noise
-- Copyright   : (c) Austin Seipp 2014
-- License     : MIT
--
-- Maintainer  : aseipp@pobox.com
-- Stability   : unstable
-- Portability : portable
--
-- Noise module for boxes. Boxes encrypt standalone messages to a
-- receiver's public key. To encrypt a message in a box, use the
-- @'seal'@ and @'open'@ primitives.
--
-- This module exports a simple, high-level interface for
-- communicating with boxes securely and easily. For a full tutorial,
-- see "Crypto.Noise.Tutorial".
--
module Crypto.Encrypt.Noise
       ( -- * Noise boxes
         -- $boxes
         -- ** Creating boxes
         seal
         -- ** Opening boxes
       , open
       ) where
import           Control.Applicative   ((<$>))
import           Data.ByteString       (ByteString)
import           Data.Word             (Word32)

import           Crypto.Noise.Internal (box_, open_)
import           Crypto.Noise.Key

--------------------------------------------------------------------------------
-- Box API

{- $boxes

Noise boxes encrypt standalone messages to a receiver identified by a
public key. When used, they have the following properties:

  [@Sender forward secret@] After encryption of a Noise box, only the
recipient can decrypt it (the sender cannot).

  [@Deniable@] The recipient of a Noise box can authenticate the
sender, but cannot produce digitally-signed evidence binding the
sender to anything.

  [@Identity hiding@] Noise boxes reveal no information about the
sender or recipient to a 3rd-party observer.

  [@High speed@] Noise usues high-speed curves and ciphers designed by
Dan Bernstein.

  [@Padded@] Noise ciphertext can be padded to avoid leaking
plaintext lengths.

  [@Built on \"Encrypt-then-MAC\" authenticated encryption@] Any
tampering with ciphertext will cause the recipient to reject the
ciphertext prior to decryption.

Internally, Noise uses SHA512, ChaCha20/8, Poly1305, and an ECDHE
function. (As of this writing, this package uses Curve25519. The true
specification mandates Curve41417, which features a higher, > 200 bit
security level.)

-}


-- | Encrypt a piece of data under a keypair for a specific
-- receiver. The optional padding length specifies how much extra
-- random data the underlying box will be padded with. A box adds a
-- minimum of 100 bytes of overhead to the payload.
--
-- Box lengths are not encoded in the output of standalone messages -
-- you must encode them some other way after encrypting your data with
-- @'seal'@ (e.g. explicitly in the encoding, or by using the file
-- length).
--
-- Note that the sender and receiver of a box, or either end of a pipe,
-- may be anonymous.
seal :: Maybe KeyPair        -- ^ Sender keys
    -> PublicKey Noise -- ^ Receiver public key
    -> Word32               -- ^ Padding length
    -> ByteString           -- ^ Plaintext
    -> IO ByteString
seal sender recvPK pad plaintext = do
  eph <- createKeypair
  fst <$> box_ Nothing eph sender recvPK pad plaintext

-- | Open an encrypted box created with @'seal'@ using a secret key,
-- optionally authenticating against a known public key of the sender.
--
-- If the secret key of the sender is provided (i.e. they are not
-- anonymous), then a box sent by any other sender will fail to open.
open :: SecretKey Noise         -- ^ Receiver secret key
     -> Maybe (PublicKey Noise) -- ^ Sender public key (optional)
     -> ByteString                   -- ^ Ciphertext
     -> Maybe ByteString
open recvSK sendPK encText = fst <$> open_ Nothing recvSK sendPK encText
