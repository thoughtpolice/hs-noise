{-# LANGUAGE DeriveGeneric #-}
module Main
       ( main -- :: IO ()
       ) where

import           Control.Monad                (forM_, liftM, void, (>=>))
import           Data.ByteString              (ByteString)
import qualified Data.ByteString              as B
import           Data.Word
import           System.FilePath
import           Text.Printf                  (printf)

import           Data.Attoparsec.Binary
import           Data.Attoparsec.ByteString   as A hiding (option)
import           Data.Default.Class
import           Data.Serialize               (encode)

import qualified Control.Concurrent.Async     as A
import           Options.Applicative          hiding (Parser)
import qualified System.IO.Streams            as S
import qualified System.IO.Streams.Attoparsec as S
import qualified System.IO.Streams.Zlib       as S

import           Crypto.Hash.BLAKE2           (blake2s)
import           Data.X509.Validation

import           Crypto.Encrypt.Noise
import           Crypto.Network.Noise
import           Crypto.Noise.Key

data Action = Encrypt FilePath [FilePath]
            | Decrypt FilePath [FilePath]
            | Hash [FilePath]
            | Keygen FilePath
            | Listen String Int
            | Connect String Int
            deriving (Show, Eq)

parseArgs :: IO Action
parseArgs = execParser opts
  where opts = info (cmds <**> helper)
                (  fullDesc
                <> progDesc "noisecat - hash, encrypt, and tunnel files/connections"
                <> header   "Noise cryptographic utility"
                <> footer   "Copyright (c) 2014 Austin Seipp. See LICENSE.txt"
                <> failureCode 1)

        cmds = hash <|> keygen <|> encrypt <|> decrypt <|> conn <|> listen
        hash =  Hash
            <$> (flag Nothing Nothing (short 's' <> help "Hash stdin or files (default)")
             *> arguments str (metavar "FILES"))
        keygen =  Keygen
            <$> strOption (short 'k' <> metavar "PATH" <> help "Generate public/private keypair")
        encrypt = Encrypt
               <$> (flag' Nothing (short 'e' <> help "Encrypt stdin or files (add .nc0 suffix)")
                *> argument str  (metavar "KEY"))
               <*> arguments str (metavar "FILES")
        decrypt = Decrypt
               <$> (flag' Nothing (short 'd' <> help "Decrypt stdin or files (must have .nc0 suffix)")
                *> argument str  (metavar "KEY"))
               <*> arguments str (metavar "FILES")
        conn = Connect
               <$> strOption (short 'c' <> metavar "ADDR" <> help "Connect to a specific host (client)")
               <*> option (short 'p' <> hidden <> value 9234)
        listen = Listen
               <$> strOption (short 'l' <> metavar "ADDR" <> help "Listen for incoming connections (server)")
               <*> option (short 'p' <> value 9234 <> metavar "PORT" <> help "Connection port")

--------------------------------------------------------------------------------
-- Packets

data Packet = Block ByteString | End
            deriving (Show, Eq)

encodePkt :: Packet -> ByteString
encodePkt End       = B.pack [0x0]
encodePkt (Block b) = B.pack [0x1] `B.append` encode l `B.append` b
  where l = fromIntegral (B.length b) :: Word32

parsePkt :: Parser (Maybe ByteString)
parsePkt = do
  ty <- anyWord8
  case ty of
    0x0 -> return Nothing
    0x1 -> anyWord32be >>= A.take . fromIntegral >>= return . Just
    _ -> fail "packet: invalid type"

packetInputStream :: S.InputStream ByteString -> IO (S.InputStream ByteString)
packetInputStream input = S.parserToInputStream parsePkt input

packetOutputStream :: S.OutputStream ByteString -> IO (S.OutputStream ByteString)
packetOutputStream output = S.makeOutputStream $ \v ->
  case v of
    Nothing -> S.write (Just $ encodePkt End) output >> S.write Nothing output
    Just x ->  S.write (Just $ encodePkt $ Block x) output

packetStreams :: (S.InputStream ByteString, S.OutputStream ByteString)
              -> IO (S.InputStream ByteString, S.OutputStream ByteString)
packetStreams (input,output)
  = (,) <$> packetInputStream input
        <*> packetOutputStream output

zlibStreams :: Int -- ^ Compression level
            -> (S.InputStream ByteString, S.OutputStream ByteString)
            -> IO (S.InputStream ByteString, S.OutputStream ByteString)
zlibStreams l (input, output)
  = (,) <$> S.decompress input
        <*> S.compress (S.CompressionLevel l) output

--------------------------------------------------------------------------------
-- Driver

main :: IO ()
main = parseArgs >>= go where
  -- Hash stdin/files
  go (Hash inp) = case inp of
    []    -> B.getContents >>= putStrLn . writeBytes . blake2s
    files -> forM_ files $ \f -> do
      b <- blake2s `liftM` B.readFile f
      putStrLn $ printf "%s %s" (writeBytes b) f

  -- Generate keys
  go (Keygen path) = do
    (PublicKey pk, SecretKey sk) <- createKeypair
    B.writeFile (path <.> "nc0pub") pk
    B.writeFile (path <.> "nc0priv") sk

  go x@(Encrypt _ _) = print x
  go x@(Decrypt _ _) = print x

  go (Connect host port) = do
    let fp1 = Fingerprint $ B.pack [ 0x11, 0xE9, 0x67, 0x19
                                   , 0xF3, 0x17, 0x4E, 0x7E
                                   , 0x93, 0x82, 0xEF, 0x96
                                   , 0xD4, 0x61, 0xBE, 0x58
                                   , 0xBC, 0x86, 0xF3, 0x55
                                   , 0x3C, 0x2C, 0x6A, 0xC0
                                   , 0x47, 0x59, 0x3C, 0xF6
                                   , 0xF3, 0x4E, 0xA7, 0x28 ]
        validCache = exceptionValidationCache
          [ (("www.foxdie.org", B.empty), fp1)
          ]
        cconf = def { confInitialResponse = Just $ validateX509_
                                              (Just "www.foxdie.org")
                                              (Just validCache)
                                              Nothing
                    }
    connect host (show port) cconf $ \(ctx, _) -> do
      let (inp, outp) = pipeContextStreams ctx
      void $ A.race (S.connect inp S.stdout)
                    (S.connect S.stdin outp)

  go (Listen host port) = do
    let sconf = def { confInitialMsg = Just (offerX509 "noise.crt")
                    }
    listen (Host host) (show port) $ \(lsock,_) -> do
    accept lsock sconf $ \(ctx, _) -> do
      let (inp, outp) = pipeContextStreams ctx
      void $ A.race (S.connect inp S.stdout)
                    (S.connect S.stdin outp)

--
-- Utils
--

writeBytes :: ByteString -> String
writeBytes = concatMap (printf "%02x") . B.unpack
