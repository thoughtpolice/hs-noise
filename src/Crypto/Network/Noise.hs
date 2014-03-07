{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE Trustworthy        #-}
-- |
-- Module      : Crypto.Network.Noise
-- Copyright   : (c) Austin Seipp 2014
-- License     : MIT
--
-- Maintainer  : aseipp@pobox.com
-- Stability   : unstable
-- Portability : portable
--
-- Noise pipes. Pipes encrypt meant for interactive communications
-- like networking sockets, and are built on boxes.
--
-- This module exports a simple, high-level interface for
-- communicating with pipes securely and easily. For a full tutorial,
-- see "Crypto.Noise.Tutorial".
--
module Crypto.Network.Noise
       ( -- * Noise pipes
         -- $pipes

         -- * TCP Socket Interface
         -- $sockets

         -- ** Client interface
         -- $client-side
         connect

         -- ** Server interface
         -- $server-side
       , serve
       , listen
       , accept
       , acceptFork

         -- ** Sending/receiving data
       , send
       , recv

         -- * @io-streams@ interface
         -- $io-streams
       , PipeMsg(..)
       , pipeClientStream
       , pipeServerStream
       , pipeContextStreams
       , pipeContextSocket
       , closeContext

         -- ** Utilities
       , PipeMsgPadder
       , randomPadStream
       , constantPadStream

         -- *** X509 certificate authentication support
         -- $x509
       , offerX509
       , validateX509
       , validateX509_

         -- * Windows support
       , NS.withSocketsDo

         -- * Types
       , Context
       , PipeConfig(..)
       , defaultPipeConfig

         -- ** Re-exported from @"Data.X509.Validation"@
       , FailedReason(..)

         -- ** Re-exported from @"Network.Simple.TCP"@
       , NS.HostPreference(..)
       , NS.HostName
       , NS.ServiceName
       , NS.Socket
       , NS.SockAddr

         -- ** Exceptions
       , IncorrectNoisePipeNegotiation
       , InvalidNoiseX509Certificate
       ) where
import           Control.Applicative
import           Control.Concurrent
import           Control.Exception
import           Control.Monad
import           Control.Monad.IO.Class (MonadIO, liftIO)
import Data.Maybe (fromMaybe)
import           Data.Either (rights)
import           Data.IORef                     (atomicWriteIORef, newIORef,
                                                 readIORef)
import           Data.Typeable

import qualified Control.Monad.Catch            as C
import           Data.Default.Class
import           Data.Serialize
import qualified Network.Simple.TCP             as NS
import qualified Network.Socket                 as NS (sClose)
import           System.Random.MWC

import qualified System.IO.Streams              as S

import           Data.ByteString                (ByteString)
import qualified Data.ByteString                as B
import qualified Data.ByteString.Char8          as B8
import           Data.Word

import           Data.PEM
import           Data.X509
import           Data.X509.Validation
import           System.X509

import Crypto.Noise.Key
import Crypto.Noise.Internal

{- $pipes

Noise pipes encrypt interactive channels like sockets. Noise pipes
have some additional benefits in addition with the protections offered
by boxes:

  [@Full forward secrecy or /full key erasure/@] Compromise of any
long-term private keys never compromises old pipes. But furthermore,
compromise of an /active/ endpoint in an ongoinng communication does
not compromise prior ciphertexts either - a Noise pipe forgets its
chain secrets upon every message.

  [@Resistance to key-compromise impersonation@] Even with a
compromised private key, the compromised party can still verify other
parties' identities in a Noise pipe.

  [@Efficient, encrypted handshakes with short roundtrip@] Handshakes
allow clients and servers to communicate after only one round trip,
offering room for validation checks or certificates.

-}

--------------------------------------------------------------------------------
-- Pipe API - io-streams

{- $io-streams

A simple @io-streams@ based interface for Noise pipes. Using these
APIs, you can turn any @'S.InputStream'@ or @'S.OutputStream'@ into an
encrypted Noise channel. Additionally, you can take a socket
@'Context'@ and obtain the underlying streams, to layer in other
transformations.

-}

chainIV :: Chain
chainIV = Chain $ B8.pack "Noise_Pipe_IV" `B.append` B.replicate 32 0x0

-- | Pipe configuration. This sets options for the long-term
-- connection and initial setup phase. Most people are probably fine
-- using @'defaultPipeConfig'@, although depending on your use case,
-- you may also want to customise the padder (probably using
-- @'randomPadStream'@).
--
-- Note that if you override the initial message/response handler, you
-- must overwrite the dual option in the other parties' handler.
data PipeConfig
  = PipeConfig { confPadding           :: Maybe Word32
                 -- ^ Padding length for the initial handshake.
                 -- Default is @'Nothing'@, which signifies a random
                 -- amount of padding between 0 and 32 bytes.
               , confKeypair           :: Maybe KeyPair
                 -- ^ Our keypair for the Noise handshake. If
                 -- unspecified, the party is considered anonymous for
                 -- the duration of the connection.
               , confExpectedKey :: Maybe (PublicKey Noise)
                 -- ^ Expected public key for the other end of the
                 -- Noise pipe. If unspecified, the party is
                 -- considered anonymous for the duration of the
                 -- connection.
               , confPadder         :: Maybe PipeMsgPadder
                 -- ^ Padding function. For every outgoing Noise
                 -- message down the pipe, this function transforms
                 -- the @'S.OutputStream'@ to yield a padding value
                 -- upstream. For example, @'randomPadStream'@
                 -- yields a random padding length for every
                 -- message, while @'constantPadStream'@ yields a
                 -- constant amount of padding for each message.
               , confInitialMsg        :: Maybe (IO ByteString)
                 -- ^ Message to send to other party in the initial
                 -- Box during the handshake.  If @'Nothing'@, then
                 -- the default message of 16 zero bytes is used.
               , confInitialResponse   :: Maybe (ByteString -> IO Bool)
                 -- ^ Handler of the initial response box from the
                 -- other party. If the result is @'False'@, then the
                 -- connection is terminated. By default, verifies the
                 -- 16 zero bytes.
               }

instance Default PipeConfig where
  def = defaultPipeConfig

-- | The default @'PipeConfig'@ uses randomized initial padding
-- length, no server keypair (anonymous), no expected client key
-- (anonymous), and no padding for messages (using
-- @'constantPadStream' 0@).
defaultPipeConfig :: PipeConfig
defaultPipeConfig
  = PipeConfig Nothing Nothing Nothing Nothing Nothing Nothing

-- | A message to send down a noise pipe - simply a message paired
-- with an amount of random padding to add to the message.
data PipeMsg = PipeMsg ByteString Word32

-- | An exception which is thrown when the Noise pipe cannot be
-- properly negotiated due to key failure or some other error.
data IncorrectNoisePipeNegotiation = IncorrectNoisePipeNegotiation
                                   deriving (Typeable)
instance Show IncorrectNoisePipeNegotiation where
  show IncorrectNoisePipeNegotiation = "Incorrect pipe negotation over noise channel"
instance Exception IncorrectNoisePipeNegotiation

-- | Type of functions which pad pipe messages.
type PipeMsgPadder = S.OutputStream PipeMsg -> IO (S.OutputStream ByteString)

-- | Given an @'S.OutputStream'@ for a @'PipeMsg'@, create an
-- @'S.OutputStream'@ that attaches a constant number of random bytes
-- to every message sent down the pipe.
--
-- For example
--
-- @let outStream' = 'constantPadStream' 0 outStream@
--
-- creates an @'S.OutputStream'@ where there is no padding for the messages
-- sent down the pipe.
constantPadStream :: Word32 -> PipeMsgPadder
constantPadStream n inp = S.makeOutputStream $ \v ->
  case v of
    Nothing -> S.write Nothing inp
    Just x  -> S.write (Just (PipeMsg x n)) inp

-- | Given an @'S.OutputStream'@ for a @'PipeMsg'@, create an
-- @'S.OutputStream'@ that attaches a random number of bytes (within
-- the specified range) to every message sent down the pipe, to make plaintext
-- analysis more difficult.
--
-- For example
--
-- @let outStream' = 'randomPadStream' (0, 64) outStream@
--
-- creates an @'S.OutputStream'@ where every message has between 0 and 64 bytes
-- of padding, chosen randomly.
randomPadStream :: Word32 -> Word32 -> PipeMsgPadder
randomPadStream lo hi inp =
  withSystemRandom   $ \rng ->
  S.makeOutputStream $ \v   ->
  case v of
    Nothing -> S.write Nothing inp
    Just x  -> do
      n <- uniformR (lo,hi) rng
      S.write (Just (PipeMsg x n)) inp


-- | Turn an @'S.InputStream'@ and @'S.OutputStream'@ into encrypted noise
-- pipes for use by clients to talk to servers.
pipeClientStream :: PipeConfig
                 -> (S.InputStream ByteString, S.OutputStream ByteString)
                 -> IO (S.InputStream ByteString, S.OutputStream ByteString)
pipeClientStream (PipeConfig pad me serverKey padder msg resp) (input, output) = do
  -- Client -> Server: C'
  eph@(ephPK, ephSK) <- createKeypair
  S.write (Just (unPublicKey ephPK)) output

  -- Client <- Server: noise_box(...)
  len1 <- decodeBE32 <$> S.readExactly 4 input
  box1 <- S.readExactly (fromIntegral len1) input

  let pt1   = open_ (Just chainIV) ephSK serverKey box1
      resp' = fromMaybe (\x -> return $ equalBS x $ B.replicate 16 0) resp
  chain1 <- case pt1 of
    Nothing     -> throwIO IncorrectNoisePipeNegotiation
    Just (xs,c) -> resp' xs >>= \v -> case v of
      True  -> return c
      False -> throwIO IncorrectNoisePipeNegotiation

  -- Client -> Server: noise_box(...)
  padding <- maybe (randRange (0, 32)) return pad
  let serverEPK = PublicKey $ B.take 32 box1
  msg' <- maybe (return $ B.replicate 16 0) id msg
  (box2, chain2) <- box_ (Just chain1) eph me serverEPK padding msg'
  let len2 = fromIntegral (B.length box2)
  S.write (Just $ encodeBE32 len2 `B.append` box2) output

  -- Now we can pipe ciphertext
  let (chainClient, chainServer) =
        B.splitAt 32 $ ncipher (B.replicate 64 0) (SecretKey $ _chainBS chain2)

  outRef <- newIORef (Chain chainClient)
  inRef  <- newIORef (Chain chainServer)

  encOutput <- S.makeOutputStream $ \v -> case v of
    Nothing -> S.write Nothing output
    Just (PipeMsg m mpad) -> do
      ch <- readIORef outRef
      (ct,chainOut) <- ciphertext_ ch mpad Nothing m
      let len = fromIntegral (B.length ct)
      S.write (Just $ encodeBE32 len `B.append` ct) output
      atomicWriteIORef outRef chainOut

  decInput <- S.makeInputStream $ do
    v <- S.peek input
    case v of
      Nothing -> return Nothing
      Just _  -> do
        len <- decodeBE32 <$> S.readExactly 4 input
        ct  <- S.readExactly (fromIntegral len) input
        ch <- readIORef inRef
        case openCiphertext ch Nothing ct of
          Nothing -> return Nothing
          Just (x, ch') -> do
            atomicWriteIORef inRef ch'
            return (Just x)

  encOutput' <- fromMaybe (constantPadStream 0) padder $ encOutput
  return (decInput, encOutput')

-- | Turn an @'S.InputStream'@ and @'S.OutputStream'@ into encrypted noise
-- pipes for use by servers to talk to clients.
pipeServerStream :: PipeConfig
                 -> (S.InputStream ByteString, S.OutputStream ByteString)
                 -> IO (S.InputStream ByteString, S.OutputStream ByteString)
pipeServerStream (PipeConfig pad me clientKey padder msg resp) (input, output) = do
  -- Server <- Client: C'
  clientEphPK <- PublicKey <$> S.readExactly 32 input

  -- Server -> Client: noise_box(...)
  padding <- maybe (randRange (0,32)) return pad
  eph@(_, ephSK) <- createKeypair
  msg' <- maybe (return $ B.replicate 16 0) id msg
  (box1,chain1) <- box_ (Just chainIV) eph me clientEphPK padding msg'
  let len1 = fromIntegral (B.length box1)
  S.write (Just $ encodeBE32 len1 `B.append` box1) output

  -- Server <- Client: noise_box(...)
  len2 <- decodeBE32 <$> S.readExactly 4 input
  box2 <- S.readExactly (fromIntegral len2) input

  let pt2 = open_ (Just chain1) ephSK clientKey box2
      resp' = fromMaybe (\x -> return $ equalBS x $ B.replicate 16 0) resp
  chain2 <- case pt2 of
    Nothing     -> throwIO IncorrectNoisePipeNegotiation
    Just (xs,c) -> resp' xs >>= \v -> case v of
      True  -> return c
      False -> throwIO IncorrectNoisePipeNegotiation

  -- Now we can pipe ciphertext
  let (chainClient, chainServer) =
        B.splitAt 32 $ ncipher (B.replicate 64 0) (SecretKey $ _chainBS chain2)

  outRef <- newIORef (Chain chainServer)
  inRef  <- newIORef (Chain chainClient)

  encOutput <- S.makeOutputStream $ \v -> case v of
    Nothing -> S.write Nothing output
    Just (PipeMsg m mpad)  -> do
      ch <- readIORef outRef
      (ct,chainOut) <- ciphertext_ ch mpad Nothing m
      let len = fromIntegral (B.length ct)
      S.write (Just $ encodeBE32 len `B.append` ct) output
      atomicWriteIORef outRef chainOut

  decInput <- S.makeInputStream $ do
    v <- S.peek input
    case v of
      Nothing -> return Nothing
      Just _  -> do
        len <- decodeBE32 <$> S.readExactly 4 input
        ct  <- S.readExactly (fromIntegral len) input
        ch <- readIORef inRef
        case openCiphertext ch Nothing ct of
          Nothing -> return Nothing
          Just (x, ch') -> do
            atomicWriteIORef inRef ch'
            return (Just x)

  encOutput' <- fromMaybe (constantPadStream 0) padder $ encOutput
  return (decInput, encOutput')

--------------------------------------------------------------------------------
-- TCP layer

{- $sockets

A simple, no-nonsense TCP interface for Noise servers/clients. This
forms the basis of the TCP interface. In the simplest case, both
clients and servers are /anonymous/ - identified not by long-term
public keys (which have been exchanged), but only by short-term
ephemeral keys. This makes the TCP layer as easy to use as any
unencrypted socket in the default case.

-}

-- | TCP connection context, containing internal connection streams.
data Context = Context NS.Socket (S.InputStream ByteString, S.OutputStream ByteString)

-- | Pull out the underlying @'S.InputStream'@ and @'S.OutputStream'@
-- from the given TCP @'Context'@. Any data written/read from these
-- streams will be encrypted/decrypted from the other side.
pipeContextStreams :: Context
                   -> (S.InputStream ByteString, S.OutputStream ByteString)
pipeContextStreams (Context _ stream) = stream

-- | Pull out the underlying @'NS.Socket'@ from the @'Context'@.
pipeContextSocket :: Context -> NS.Socket
pipeContextSocket (Context sock _) = sock

-- | Close the given @'Context'@.
closeContext :: Context -> IO ()
closeContext (Context sock _) = NS.sClose sock

--
-- Client
--

{- $client-side

Here's an example of a Noise client:

@
'connect' \"www.example.org\" \"80\" 'defaultPipeConfig' $ \\(ctx, remoteAddr) -> do
  putStrLn $ \"Connection established to \" ++ show remoteAddr
  -- Now you can use connSock as you see fit with 'send' and 'recv'.
  -- The socket handle will automatically be closed when it goes out of scope.
@
-}

-- | Connect to a Noise-secured TCP server and use the connection.
--
-- Any acquired network resources are properly closed and discarded
-- when done or in case of exceptions.
connect :: (MonadIO m, C.MonadCatch m)
      => NS.HostName      -- ^ Server hostname
      -> NS.ServiceName   -- ^ Server port
      -> PipeConfig       -- ^ Client configuration
      -> ((Context, NS.SockAddr) -> m r) -- ^ Connection handler
      -> m r
connect hostPref serviceName conf k =
  NS.connect hostPref serviceName $ \(socket, sockAddr) -> do
    streams <- liftIO $ (S.socketToStreams >=> pipeClientStream conf) socket
    k ((Context socket streams), sockAddr)

--
-- Server
--

{- $server-side

Here's an example of a Noise server:

@
'serve' ('NS.Host' \"127.0.0.1\") \"8000\" 'defaultPipeConfig' $ \\(ctx, remoteAddr) -> do
  putStrLn $ \"Noise connection established from \" ++ show remoteAddr
  -- Now you may use 'ctx' as you please within this scope,
  -- possibly using 'recv' and 'send' to interact with the remote end.
@
-}

-- | Start a Noise-secured TCP server which accepts incoming
-- connections and handles each of them concurrently in different
-- threads.
--
-- Any acquired network resources are properly closed and discarded
-- when done or in case of exceptions.
--
-- Internally, this function just performs @'listen'@ and
-- @'acceptFork'@.
serve :: MonadIO m
      => NS.HostPreference -- ^ Preferred host to bind on
      -> NS.ServiceName    -- ^ Service port
      -> PipeConfig        -- ^ Server configuration
      -> ((Context, NS.SockAddr) -> IO ()) -- ^ Connection handler
      -> m ()
serve hp port conf k = liftIO $
  listen hp port $ \(lsock,_) ->
    forever $ acceptFork lsock conf k

-- | Bind a TCP listening socket and use it
--
-- The listening socket is closed when done or in case of exceptions.
--
-- Note: @'N.maxListenQueue'@ is tipically 128, which is too small for
-- high performance servers. So, we use the maximum between
-- 'N.maxListenQueue' and 2048 as the default size of the listening
-- queue. The @'NS.NoDelay'@ and @'NS.ReuseAddr'@ options are set on the
-- socket.
listen :: (MonadIO m, C.MonadCatch m)
       => NS.HostPreference -- ^ Preferred host to bind
       -> NS.ServiceName -- ^ Port identifier
       -> ((NS.Socket, NS.SockAddr) -> m r) -- ^ Handler for listening socket
       -> m r
listen hostPref serviceName k = NS.listen hostPref serviceName k

-- | Accept a single incoming connection and use it.
--
-- The connection socket is closed when done or in case of exceptions.
accept :: (MonadIO m, C.MonadCatch m)
       => NS.Socket   -- ^ Listening and bound socket
       -> PipeConfig  -- ^ Server configuration
       -> ((Context, NS.SockAddr) -> m r) -- ^ Handler for incoming connection.
       -> m r
accept sock conf k = NS.accept sock $ \(socket, sockAddr) -> do
  streams <- liftIO $ (S.socketToStreams >=> pipeServerStream conf) socket
  k ((Context socket streams), sockAddr)

-- | Accept a single incoming connection and use it in another thread.
--
-- The connection socket is closed when done or in case of exceptions.
acceptFork :: MonadIO m
           => NS.Socket  -- ^ Listening and bound socket
           -> PipeConfig -- ^ Server configuration
           -> ((Context, NS.SockAddr) -> IO ()) -- ^ Handler for incoming connection.
           -> m ThreadId
acceptFork sock conf k = NS.acceptFork sock $ \(socket, sockAddr) -> do
  streams <- liftIO $ (S.socketToStreams >=> pipeServerStream conf) socket
  k ((Context socket streams), sockAddr)

--
-- Sending/receiving data
--

-- | Receives data over the connection, decrypts it and returns the
-- resulting @'ByteString'@. This receives a single Noise message.
--
-- Returns @'Nothing'@ if the remote end closed the connection or
-- end-of-input was reached.
recv :: MonadIO m => Context -> m (Maybe ByteString)
recv (Context _ (input, _)) = liftIO (S.read input)

-- | Encrypts the given @'ByteString'@, and writes the bytes to the
-- socket in a single message. The data can also be padded with random
-- data to obscure the plaintext length.
send :: MonadIO m
     => Context    -- ^ Connection context
     -> ByteString -- ^ Message
     -> m ()
send (Context _ (_, output)) bs = liftIO (S.write (Just bs) output)

--------------------------------------------------------------------------------
-- X509 support

{- $x509

Simple X509 support for pipe handshakes. The two functions
@'offerX509'@ and @'validateX509'@ provide hooks you can use with
@'PipeConfig'@ to do X509 certificate validation as part of the
initial Noise handshake. In addition, the extra @'validateX509_'@
function gives you more control over the client validation (to allow,
for example, self-signed certificates).

This verification API can work for verifying server certificates to
clients, vice versa, or both.

-}

readSignedObject :: FilePath -> IO [SignedExact Certificate]
readSignedObject file = do
    content <- B.readFile file
    let objs = either error (map (decodeSignedObject . pemContent)) $ pemParseBS content
    forM_ objs $ \o -> do
      case o of
        Left err -> throwIO $ InvalidNoiseX509Certificate ("Could not decode X509 certificate: " ++ err)
        _        -> return ()
    return (rights objs)

-- | Offer up an X509 certificate chain as part of the initial
-- handshake. Given a @'FilePath'@ specifying a certificate, this will
-- cause the configured party to issue the certificate as part of its
-- initial message.
--
-- Note the other party MUST validate this response using
-- @'validateX509'@ in their @'confInitialResponse'@ setting.
--
-- When this function cannot parse the certificate chain correctly
-- (for example, using an invalid file), it will throw an
-- @'InvalidNoiseX509Certificate'@.
offerX509 :: FilePath
              -- ^ Path to the server certificate chain to offer
              -- during the handshake, in PEM format.
              -> IO ByteString
              -- ^ Resulting encoded certificate chain.
offerX509 path = do
  objs <- readSignedObject path
  let CertificateChainRaw cc = encodeCertificateChain (CertificateChain objs)
  return (encode cc)

-- | Simple X509 certificate chain validation for initial handshakes.
--
-- This is a simple, easy-to-use client API that allows you to
-- validate server-offered certificates using the system certificate
-- store. All it needs is the expected FQDN of the certificate.
--
-- If you need more control (for example, TOFU policies or validation
-- exceptions), please use @'validateX509_'@ instead.
--
-- Note the server MUST send the initial certificate using
-- @'offerX509'@ in their @'confInitialMsg'@ setting.
--
-- When this function cannot validate the X509 certificate offered to
-- it, it will throw an @'InvalidNoiseX509Certificate'@ exception.
validateX509 :: Maybe String
             -- ^ Optional certificate FQDN to verify.
             -> ByteString
             -- ^ Input certificate
             -> IO Bool
validateX509 x xs = validateX509_ x Nothing Nothing xs

-- | X509 certificate validation. This is the \'extended\' version of
-- the basic @'x509ClientValidate'@ API, allowing more control. Given
-- an optional hostname and the input certificate chain (encoded), as
-- well as control over the validation cache and a predicate, this
-- validates the certificate against the system store.
--
-- Note the server MUST send the initial certificate using
-- @'x509ServerMsg'@ in their @'serverInitialMsg'@ setting.
--
-- When this function cannot validate the X509 certificate offered to
-- it, it will throw an @'InvalidNoiseX509Certificate'@ exception.
validateX509_ :: Maybe String
              -- ^ Optional certificate FQDN to verify.
              -> Maybe ValidationCache
              -- ^ Optional X509 validation cache. You may use
              -- this to enforce self-signing exceptions or TOFU
              -- (\"Trust On First Use\") validation.
              --
              -- The default cache is
              -- @'Data.X509.Validation.exceptionValidationCache'
              -- []@
              --
              -- Note that fingerprints by default use SHA256,
              -- not SHA1.
              -> Maybe ([FailedReason] -> IO Bool)
              -- ^ Optional testing predicate. If for some reason
              -- you /expect/ the validation to fail, you can use
              -- this to check specific results. You're
              -- encouraged to never touch this.
              --
              -- If you need a self signed certificate, you
              -- should use the X509
              -- @'Data.X509.Validation.ValidationCache'@
              -- instead (which also lets you do TOFU).
              --
              -- The default predicate is @(\x -> if x == []
              -- then return True else
              -- 'Control.Exception.throwIO'
              -- 'InvalidNoiseX509Certificate' ...)@ - i.e. the
              -- certificate must properly validate.
              -> ByteString
              -- ^ Input certificate
              -> IO Bool
validateX509_ hostName vcache predicate inp = case decode inp of
  Left err -> fail $ "noise: Couldn't parse raw x509 cert: " ++ err
  Right xs -> case decodeCertificateChain (CertificateChainRaw xs) of
    Left err -> fail $ "noise: Couldn't decode raw x509 cert: " ++ show err
    Right cc -> do
      let vcache' = fromMaybe (exceptionValidationCache []) vcache
      store <- getSystemCertificateStore
      failed <- validateDefault store vcache'
                  (maybe ("", B.empty) (\f -> (f, B.empty)) hostName) cc
      let defaultCheck x = if x == [] then return True else
                             throwIO (InvalidNoiseX509Certificate $ show x)
      res <- fromMaybe defaultCheck predicate $ failed
      return res

-- | Exception throw by clients when an invalid X509 certificate is offered. This may also be thrown by the server when it
-- cannot decode the X509 certificate.
data InvalidNoiseX509Certificate = InvalidNoiseX509Certificate String
                                 deriving (Typeable)
instance Show InvalidNoiseX509Certificate where
  show (InvalidNoiseX509Certificate s) = "Invalid X509 certificate offered over pipe: " ++ s
instance Exception InvalidNoiseX509Certificate
