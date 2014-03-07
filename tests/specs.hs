module Main
       ( main  -- :: IO ()
       ) where
import           Control.Exception        (evaluate)
import           Control.Monad
import           Data.Function
import           Data.List                as List
import           Data.Maybe
import           Data.Word
import           Debug.Trace
import           Prelude                  as Prelude

import qualified Data.ByteString          as B
import qualified Data.ByteString.Char8    as B8
import           System.Random.MWC

import           Crypto.Encrypt.Noise
import           Crypto.Noise.Key

import           Test.Hspec
import           Test.QuickCheck
import           Test.QuickCheck.Property (morallyDubiousIOProperty)

--------------------------------------------------------------------------------
-- Driver

main :: IO ()
main = withSystemRandom $ \rng -> hspec . parallel $ do
  describe "keys" $ do
    they "are 32 bytes in length" $ do
      (PublicKey pk, SecretKey sk) <- createKeypair
      B.length pk `shouldBe` 32
      B.length sk `shouldBe` 32

  describe "boxes" $ do
    describe "seal" $ do
      context "creates a valid box" $ do
        it "with anonymous senders" $ property $ \bs ->
          morallyDubiousIOProperty $ do
            (pk, sk) <- createKeypair
            b <- seal Nothing pk 0 $ B8.pack bs
            return (open sk Nothing b == Just (B8.pack bs))

        it "with identified senders" $ property $ \bs ->
          morallyDubiousIOProperty $ do
            sendr@(pk1, sk1) <- createKeypair
            recvr@(pk2, sk2) <- createKeypair
            b <- seal (Just sendr) pk2 0 $ B8.pack bs
            return (open sk2 (Just pk1) b == Just (B8.pack bs))

      context "when given a message" $ do
        it "seals it in a box" $ do
          (pk, sk) <- createKeypair
          b <- seal Nothing pk 0 $ B.pack [0,1,2,3,4]
          void (evaluate b)

        it "adds 100 bytes of overhead" $ do
          (pk, sk) <- createKeypair
          b <- seal Nothing pk 0 $ B.pack [0,1,2,3,4]
          B.length b `shouldBe` (100+5)

      context "when adding padding" $
        it "adds the correct amount" $ property $ \bs ->
          morallyDubiousIOProperty $ do
            (pk, sk) <- createKeypair
            r <- uniformR (0, 512) rng
            b <- seal Nothing pk r $ B8.pack bs
            return $ B.length b == fromIntegral (100+r+(fromIntegral $ length bs))

    describe "open" $ do
      context "when provided with a valid box" $
        it "can open it" $ do
          (pk, sk) <- createKeypair
          b <- seal Nothing pk 0 $ B.pack [0,1,2,3,4]
          open sk Nothing b `shouldBe` Just (B.pack [0,1,2,3,4])

      context "when provided with an invalid box" $
        it "fails to open it" $ pendingWith "laziness"

      context "when provided a box that's been tampered with" $
        it "fails to open it" $ pendingWith "laziness"

      context "fails to open a box" $ do
        it "when presented with an invalid receiver key" $ pending
        it "when presented with an invalid sender key" $ pending
        it "when it's anonymous and tries to use a key" $ pending
        it "when it's identified and tries to open anonymously" $ pending

  describe "pipes" $ return ()

--------------------------------------------------------------------------------
-- Utilities

they :: Example a => String -> a -> Spec
they = it
