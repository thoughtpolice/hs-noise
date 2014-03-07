-- |
-- Module      : Crypto.Noise.Internal
-- Copyright   : (c) Austin Seipp 2014
-- License     : MIT
--
-- Maintainer  : aseipp@pobox.com
-- Stability   : unstable
-- Portability : portable
--
-- Noise internal module.
--
module Crypto.Noise.Internal where
import           Data.Bits
import           Data.Serialize
import           System.Random.MWC

import           Data.ByteString                (ByteString)
import qualified Data.ByteString                as B
import qualified Data.ByteString.Char8          as B8
import           Data.Word

import qualified Crypto.DH.Curve25519           as Curve25519
import           Crypto.Encrypt.Stream.ChaCha20 (ChaCha20)
import qualified Crypto.Encrypt.Stream.ChaCha20 as ChaCha20
import qualified Crypto.Hash.SHA                as SHA
import           Crypto.Key
import qualified Crypto.MAC.Poly1305            as Poly1305
import           Crypto.Nonce
import           System.Crypto.Random           (randombytes)

import           Crypto.Noise.Key

--------------------------------------------------------------------------------
-- Types

data Header
  = Header { _hdrPK          :: PublicKey Noise
           , _hdrEncSenderPK :: ByteString
           , _hdrMAC         :: Poly1305.Auth
           }

instance Serialize Header where
  put (Header (PublicKey pk) espk (Poly1305.Auth mac)) = do
    putByteString pk
    putByteString espk
    putByteString mac

  get = do
    pk   <- getBytes 32
    espk <- getBytes 32
    mac  <- getBytes 16
    return (Header (PublicKey pk) espk (Poly1305.Auth mac))

data Ciphertext
  = Ciphertext { _ctData :: ByteString
               , _ctMAC  :: Poly1305.Auth
               }

data Box
  = Box { _boxHdr :: Header
        , _boxCt  :: Ciphertext
        }

newtype Chain = Chain { _chainBS :: ByteString }
              deriving (Eq, Show, Ord)

--------------------------------------------------------------------------------
-- Internal APIs

header :: Chain                -- Chain input
       -> KeyPair              -- Ephemeral keys
       -> Maybe KeyPair        -- Sender keys
       -> PublicKey Noise -- Receiver public key
       -> (Header, Chain)
header (Chain chain) (ephPK, ephSK) senderKeys recvPK
  = (Header ephPK encSendPK mac, key2)
  where
    sendPK = maybe ephPK fst senderKeys

    -- Key exchange
    dh1 = curve25519 ephSK recvPK
    dh2 = maybe dh1 (\(_,s) -> curve25519 s recvPK) senderKeys

    -- Key derivation, step one
    key1 = SecretKey $ nhash (txt `B.append` dh1 `B.append` chain)
      where txt = B8.pack "Noise_Box_KDF1"

    -- Block encryption, key derivation step two
    (chainTmp, macKey, encSendPK)
      = ( B.take 32 block
        , B.take 32 $ B.drop 32 block
        , B.drop 64 block)
      where
        block = ncipher datum key1
        datum = B.replicate 64 0x0 `B.append` (unPublicKey sendPK)

    -- MAC derivation
    mac = Poly1305.authenticate (SecretKey macKey) dataBlock
      where dataBlock = (unPublicKey ephPK) `B.append` encSendPK

    -- Key derivation, step three
    key2 = Chain $ nhash (txt `B.append` dh2 `B.append` chainTmp)
      where txt = B8.pack "Noise_Box_KDF2"

ciphertext :: Chain
           -> Word32
           -> Maybe Header
           -> ByteString
           -> IO (Ciphertext, Chain)
ciphertext (Chain chain) pad hdr plaintext = do
  padding <- randombytes (fromIntegral pad)
  let
    (chainOut, macKey, encText)
      = ( B.take 32 block
        , B.take 32 $ B.drop 32 block
        , B.drop 64 block)
      where
        block = ncipher datum (SecretKey chain)
        datum =      B.replicate 64 0x0
          `B.append` encode pad
          `B.append` padding
          `B.append` plaintext
    mac = Poly1305.authenticate (SecretKey macKey) dataBlock
      where dataBlock = maybe B.empty encode hdr `B.append` encText

  return (Ciphertext encText mac, Chain chainOut)

ciphertext_ :: Chain
            -> Word32
            -> Maybe Header
            -> ByteString
            -> IO (ByteString, Chain)
ciphertext_ chain pad hdr pt = do
  (Ciphertext et (Poly1305.Auth m), chainOut) <- ciphertext chain pad hdr pt
  return (et `B.append` m, chainOut)

boxInternal :: Maybe Chain
     -> KeyPair              -- ^ Ephemeral keys
     -> Maybe KeyPair        -- ^ Sender keys
     -> PublicKey Noise -- ^ Receiver public key
     -> Word32               -- ^ Padding length
     -> ByteString           -- ^ Plaintext
     -> IO (Box, Chain)      -- ^ Output
boxInternal chain eph sender recvPK pad plaintext = do
  let (hdr, key2) = header chainIn eph sender recvPK
  (ct, chainOut) <- ciphertext key2 pad (Just hdr) plaintext
  return (Box hdr ct, chainOut)
  where
    chainIn = maybe (Chain chain1) id chain
      where chain1 = B8.pack "Noise_Box_IV" `B.append` B.replicate 32 0x0

box_ :: Maybe Chain
     -> KeyPair
     -> Maybe KeyPair          -- ^ Sender keys
     -> PublicKey Noise   -- ^ Receiver public key
     -> Word32                 -- ^ Padding length
     -> ByteString             -- ^ Plaintext
     -> IO (ByteString, Chain)
box_ chain eph sender recvPK pad plaintext = do
  (Box hdr ct, chainOut) <- boxInternal chain eph sender recvPK pad plaintext
  let
    (Header (PublicKey hdrPK) hdrESPK (Poly1305.Auth hdrMAC)) = hdr
    (Ciphertext ct' (Poly1305.Auth ctMAC)) = ct
    result =     hdrPK
      `B.append` hdrESPK
      `B.append` hdrMAC
      `B.append` ct'
      `B.append` ctMAC
  return (result, chainOut)

openCiphertext :: Chain
               -> Maybe ByteString
               -> ByteString
               -> Maybe (ByteString, Chain)
openCiphertext (Chain chain) hdr ct = verifyMAC
  where
    (ctxt, ctMAC) = B.splitAt (B.length ct - 16) ct
    body = maybe B.empty id hdr `B.append` ctxt

    -- Block encryption, key derivation step two
    (chainOut, macKey2, plaintxt)
      = ( B.take 32 block
        , B.take 32 $ B.drop 32 block
        , B.drop 64 block)
      where
        block = ncipher (B.replicate 64 0x0 `B.append` ctxt) (SecretKey chain)

    -- MAC verification
    verifyMAC :: Maybe (ByteString, Chain)
    verifyMAC =
      case Poly1305.verify (SecretKey macKey2) a body of
        True  ->
          case decode (B.take 4 plaintxt) of
            Left _  -> Nothing
            Right x -> Just $ ( B.drop (fromIntegral (x :: Word32) + 4) plaintxt
                              , Chain chainOut )
        False -> Nothing
      where a = Poly1305.Auth ctMAC


open_ :: Maybe Chain
      -> SecretKey Noise         -- ^ Receiver secret key
      -> Maybe (PublicKey Noise) -- ^ Sender public key (optional)
      -> ByteString
      -> Maybe (ByteString, Chain)
open_ chain recvSK sendPK encText =
     verifyMAC
  >> verifyDecKey sendPK
  >> verifyCT
  where
    ephPK       = PublicKey $ B.take 32 encText
    encSenderPK = B.take 32 $ B.drop 32 encText
    hdrMAC      = Poly1305.Auth $ B.take 16 $ B.drop 64 encText

    chainIn = maybe chain1 _chainBS chain
      where chain1 = B8.pack "Noise_Box_IV" `B.append` B.replicate 32 0x0

    -- Key exchange
    dh1 = curve25519 recvSK ephPK
    dh2 = maybe dh1 (curve25519 recvSK) sendPK

    -- Key derivation, step one
    key1 = SecretKey $ nhash (txt `B.append` dh1 `B.append` chainIn)
      where txt = B8.pack "Noise_Box_KDF1"

    -- Block encryption, key derivation step two
    (chainTmp, macKey)
      = ( B.take 32 block
        , B.drop 32 block)
      where block = ncipher (B.replicate 64 0x0) key1

    -- MAC verification
    verifyMAC :: Maybe Bool
    verifyMAC =
      case Poly1305.verify (SecretKey macKey) hdrMAC (B.take 64 encText) of
        True  -> Just True
        False -> Nothing

    senderKey = PublicKey $ B.drop 64 (ncipher block key1)
      where block = chainTmp `B.append` macKey `B.append` encSenderPK

    -- Sender key verification
    verifyDecKey :: Maybe (PublicKey Noise) -> Maybe Bool
    verifyDecKey Nothing
      | equalPK senderKey ephPK = Just True
      | otherwise               = Nothing
    verifyDecKey (Just pk)
      | equalPK senderKey pk = Just True
      | otherwise            = Nothing

    -- Key derivation, step three
    key2 = Chain $ nhash (txt `B.append` dh2 `B.append` chainTmp)
      where txt = B8.pack "Noise_Box_KDF2"

    verifyCT :: Maybe (ByteString, Chain)
    verifyCT = openCiphertext key2 (Just $ B.take 80 encText) (B.drop 80 encText)

--------------------------------------------------------------------------------
-- Utils

randRange :: (Word32, Word32) -> IO Word32
randRange rng = withSystemRandom (\x -> uniformR rng x :: IO Word32)
{-# INLINE randRange #-}

encodeBE32 :: Word32 -> ByteString
encodeBE32 = encode

decodeBE32 :: ByteString -> Word32
decodeBE32 x
  | B.length x /= 4 = error "Invalid length!"
  | otherwise = either (error "Could not decode length!") id (decode x)

equalPK :: PublicKey t -> PublicKey t -> Bool
equalPK (PublicKey x) (PublicKey y) = equalBS x y

equalBS :: ByteString -> ByteString -> Bool
equalBS x y = B.length x == B.length y && 0 == sum (B.zipWith xor x y)

curve25519 :: SecretKey Noise -> PublicKey Noise -> ByteString
curve25519 = Curve25519.curve25519

nhash :: ByteString -> ByteString
nhash = B.take 32 . SHA.sha512

ncipher :: ByteString -> SecretKey ChaCha20 -> ByteString
ncipher inp key = ChaCha20.encrypt nonce inp key
  where nonce = Nonce $ B.pack [0,0,0,0,0,0,0,0]
