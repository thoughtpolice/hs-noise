-- |
-- Module      : Crypto.Noise.Key
-- Copyright   : (c) Austin Seipp 2014
-- License     : MIT
--
-- Maintainer  : aseipp@pobox.com
-- Stability   : unstable
-- Portability : portable
--
-- Key generation for noise boxes/pipes.
--
module Crypto.Noise.Key
       ( Noise
       , KeyPair
       , createKeypair
         -- ** Re-exported of @"Crypto.Key"@
       , PublicKey(..)
       , SecretKey(..)
       ) where
import           Crypto.Key (PublicKey(..), SecretKey(..))
import           Crypto.DH.Curve25519           (Curve25519)
import qualified Crypto.DH.Curve25519           as Curve25519

--------------------------------------------------------------------------------
-- Keys

-- | The type of Noise keys.
type Noise   = Curve25519 -- :(

-- | Simple alias for a Noise keypair
type KeyPair = (PublicKey Noise, SecretKey Noise)

-- | Create public/private keys for use with noise boxes or noise
-- pipes.
createKeypair :: IO (PublicKey Noise, SecretKey Noise)
createKeypair = Curve25519.createKeypair
