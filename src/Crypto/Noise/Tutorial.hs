-- |
-- Module      : Crypto.Noise.Tutorial
-- Copyright   : (c) Austin Seipp 2014
-- License     : MIT
--
-- Maintainer  : aseipp@pobox.com
-- Stability   : experimental
-- Portability : portable
--
-- Noise is a suite of cryptographic protocols similar in spirit to
-- NaCl's @crypto_box@, or network solutions like TLS, but simpler,
-- faster, with higher-security elliptic-curve cryptography, and
-- stronger guarantees about deniability and identity hiding.
--
-- This protocol has many favorable security and usability properties,
-- including:
--
--   [@Sender forward secrecy@] After encryption of a Noise box, only the
-- recipient can decrypt it (the sender cannot).
--
--   [@Deniable@] The recipient of a Noise box can authenticate the
-- sender, but cannot produce digitally-signed evidence binding the
-- sender to anything.
--
--   [@Identity hiding@] Noise boxes reveal no information about the
-- sender or recipient to a 3rd-party observer.
--
--   [@High speed@] Noise usues high-speed curves and ciphers designed by
-- Dan Bernstein.
--
--   [@Padded@] Noise ciphertext can be padded to avoid leaking
-- plaintext lengths.
--
--   [@Built on \"Encrypt-then-MAC\" authenticated encryption@] Any
-- tampering with ciphertext will cause the recipient to reject the
-- ciphertext prior to decryption.
--
-- Noise pipes are built on Noise boxes and designed for interactive
-- communications, and in addition to the above, Noise pipes offer the
-- following benefits:
--
--   [@Full forward secrecy or /full key erasure/@] Compromise of any
-- long-term private keys never compromises old pipes. But furthermore,
-- compromise of an /active/ endpoint in an ongoinng communication does
-- not compromise prior ciphertexts either - a Noise pipe forgets its
-- chain secrets upon every message.
--
--   [@Resistance to key-compromise impersonation@] Even with a
-- compromised private key, the compromised party can still verify other
-- parties' identities in a Noise pipe.
--
--   [@Efficient, encrypted handshakes with short roundtrip@] Handshakes
-- allow clients and servers to communicate after only one round trip,
-- offering room for validation checks or certificates.
--
-- This package offers:
--
--   [@A high-level box API@] Boxes are created using the simple
--   @'Crypto.Encrypt.Noise.seal'@ and @'Crypto.Encrypt.Noise.open'@
--   primitives. Boxes are encrypted, authenticated, and optionally
--   anonymous. Furthermore, boxes are /forward secret/: only the
--   receiver (identified by the receiving public key) can open them.
--
--   [@A simplistic networking API@] Noise pipes can be utilized
--   easily on top of TCP sockets using the
--   @'Crypto.Network.Noise.connect'@ and
--   @'Crypto.Network.Noise.serve'@ primitives. This makes it easy to
--   write networking services with transparent encryption support,
--   built on familiar @'Crypto.Network.Noise.send'@ and
--   @'Crypto.Network.Noise.recv'@ primitives.
--
--   [@A high-level io-streams API@] The networking API internally is
--   built off a high-level API based on @io-streams@, which makes
--   encrypting data over a pipe as easy as reading/writing to an
--   @'System.IO.Streams.InputStream'@ or
--   @'System.IO.Streams.OutputStream'@. This also integrates with the
--   networking API, making it easy to layer in extra transformations
--   (compression, a high level packet format, etc).
--
--   [@X509 certificate support@] This package makes it easy for noise
--   pipes to automatically validate X509 certificates as part of the
--   handshake. Parties can begin exchanging data after only one round
--   trip. In this case, the certificate is offered, which is
--   validated before continuing.
--
-- For more information visit <https://github.com/trevp/noise/wiki>.
--
module Crypto.Noise.Tutorial
       ( -- * Introduction
         -- $introduction

         -- ** Box API
         -- $boxes

         -- ** @network@ API
         -- $networking

         -- ** @io-streams@ API
         -- $io-streams

         -- ** Padding
         -- $padding

         -- ** Initial message support
         -- $initial-msgs

         -- *** X509 support
         -- $x509

         -- * Differences from the standard
         -- $differences

         -- * Other notes
         -- $othernotes
       ) where

-- $setup
-- >>> import Crypto.Noise.Key
-- >>> import Crypto.Encrypt.Noise
-- >>> import Data.ByteString.Char8
-- >>> sender@(senderPK, senderSK)      <- createKeypair
-- >>> receiver@(receiverPK, receiverSK) <- createKeypair

{- $introduction

The @noise@ package defines two sets of APIs: boxes and pipes. Boxes
handle standalone messages, and pipes encrypt communication channels.

To begin, a sender and a receiver must create a keypair:

@
sender@(senderPK, senderSK)       <- 'Crypto.Noise.Key.createKeypair'
receiver@(receiverPK, receiverSK) <- 'Crypto.Noise.Key.createKeypair'
@

Send the public keys around, and keep the private keys safe.

-}

{- $boxes

Boxes are created using @'Crypto.Encrypt.Noise.seal'@, and opened
using @'Crypto.Encrypt.Noise.open'@:

>>> b <- seal (Just sender) receiverPK 32 $ pack "Hello world!"
>>> print $ open receiverSK (Just senderPK) b
Just "Hello world!"

When creating a box, you specify the sending keypair, the receiving
public key, the amount of random padding you want (to obscure the
plaintext length), and the message. To open it, you specify the secret
key of the receiving party, and the public key of the sender.

Attempting to open a box from someone other than the sender will
result in failure.

Senders may also be /anonymous/, where the sender does not specify a
long-term key pair:

>>> b <- seal Nothing receiverPK 32 $ pack "Hello world!"
>>> print $ open receiverSK Nothing b
Just "Hello world!"

In the above example, the sender of the box is anonymous without a
keypair, and attempting to use a value other than @Nothing@ as the key
will error. When the sender is anonymous, they are only identified by
a short-term ephemeral key, which is used only once for the
corresponding box.

Once you have encrypted a value using @'Crypto.Encrypt.Noise.seal'@,
it can only be decrypted by the receiving party with the secret
key. This property means that boxes are /forward secret/: once you are
done creating them and have \'forgotten\' the message, you cannot
recover it. Furthermore, boxes are /deniable/: a recipient of a box
can authenticate the sender. But they cannot produce signed evidence
binding the sender to anything. Finally, boxes do not produce any
evidence of who created them or who the receiver is, and resist
tampering with a strong MAC.

-}

{- $networking

@noise@ provides a simple, high-level networking API by default that
closely mimmicks the traditional @network@ API, but is more convenient
to use as it will control closing sockets, and handle exception
handling.

To start a server in the most simple case, all you need is the
@'Crypto.Network.Noise.serve'@ primitive, with a default
configuration:

@
'Crypto.Network.Noise.serve' ('Crypto.Network.Noise.Host' \"127.0.0.1") \"9123\" 'Crypto.Network.Noise.defaultPipeConfig' $ \\(ctx, remoteAddr) -> do
  putStrLn $ \"Noise connection established from \" ++ show remoteAddr
  'Crypto.Network.Noise.send' ctx $ 'Data.ByteString.Char8.pack' \"Hello world!\"
@

Next, you can connect a client and use the familiar
@'Crypto.Network.Noise.send'@ and @'Crypto.Network.Noise.recv'@
primitives to talk over the handle:

@
'Crypto.Network.Noise.connect' \"www.example.org\" \"9123\" 'Crypto.Network.Noise.defaultPipeConfig' $ \\(ctx, remoteAddr) -> do
  putStrLn $ "Connection established to " ++ show remoteAddr
  msg <- 'Crypto.Network.Noise.recv' ctx
  putStrLn $ "Got message: " ++ show msg
@

You're done! Both ends are completely encrypted. Furthermore, the
server can accept many incoming concurrent connections.

In the above example (and by default), pipes are /anonymous/ like
Noise boxes - parties are only identified by short-term ephemeral
keys. This is the default configuration in the above example, with no
extra options needed. Unlike boxes (which obviously require a key to
open), /both/ sides of a Noise pipe can function anonymously, or only
one of them can (servers or clients). In all cases, pipes are
authenticated to the specified parties keys only (long term or
ephemeral). This makes Noise as easy to use as an unencrypted TCP
socket (and easier than TLS even), while offering considerably better
security in all aspects.

Note that without long-term keys, you can still be affected by a
Man-in-the-Middle attack - attackers can intercept your packets, and
give you a short-term ephemeral key claiming to be another party. But
unlike protocols such as CurveCP, Noise does not /require/ long-term
identies for services, nor clients: identification and authentication
is flexible (as we'll see later).

Anonymous clients and servers do have a bonus: they cut down on the
required number of key exchanges. Underneath, Noise uses a \"Triple
Diffie-Hellman\" agreement that does a 3-way DHE exchange (this 3DHE
construction is the secret behind Noise's deniability, simplicity, and
power). If either side of a particular pipe is anonymous, this count
is reduced to two or even one during the initial handshake.

If you'd like to authenticate clients or servers with long-term public
keys, you only need to specify this in the configuration, after
sharing public keys however you want (over the phone, in meatspace, or
with an Instagr.am picture). First, generate the long-term keys:

@
(public, private) <- 'Crypto.Noise.Key.createKeypair'
@

Keep the private key somewhere safe. It's only 32 bytes long, so it
isn't exactly huge. Distribute the public key to whoever needs it.

Once you've done that, just specify the keys in your
configuration. For example, to specify the long-term keys for the
server:

@
let sconf = 'Crypto.Network.Noise.defaultPipeConfig'
              { 'Crypto.Network.Noise.confKeypair' = Just (public, private)
              }
@

and use @'Crypto.Network.Noise.serve'@ as usual.

Next, make the the client specifies the server's long-term public key
in its connection:

@
serverPublicKey <- 'Data.ByteString.readFile' \"keys/ServerKey.pk\"
let cconf = 'Crypto.Network.Noise.defaultPipeConfig'
              { 'Crypto.Network.Noise.confExpectedKey' = Just serverPublicKey
              }
@

Any attempt to connect to a server not identified by this public key
will be rejected.

You can also do this in reverse: a client can have a long-term key and
a server will only accept connections from this key. Likewise, any
client connections not identified by this key are rejected:

@
let sconf = 'Crypto.Network.Noise.defaultPipeConfig'
              { 'Crypto.Network.Noise.confExpectedKey' = Just clientPublicKey
              }

let cconf = 'Crypto.Network.Noise.defaultPipeConfig'
              { 'Crypto.Network.Noise.confKeypair' = Just (public, private)
              }
@

Naturally, combining the two results in a fully authenticated tunnel.

Note that if a server expects a particular client identified by a
long-term key, in most cases little point in using
@'Crypto.Network.Noise.serve'@ as it continuously serves
connections. If you want single connections, you can use the
@'Crypto.Network.Noise.listen'@ and @'Crypto.Network.Noise.accept'@
primitives instead.

-}

{- $io-streams

The networking API is powered underneath by the @io-streams@ API,
which you can use to build your own Noise pipes over any
@'System.IO.Streams.InputStream'@ and
@'System.IO.Streams.OutputStream'@. This transformation takes existing
streams, does the negotiation over them, and returns the resulting
encrypted streams.

A noise pipe comes in two flavors: a server pipe, and a client
pipe. At the end of the day, there isn't really a difference between
the two: it's just a matter of having the two duplex channels. To
create a server pipe, first specify your
@'Crypto.Network.Noise.PipeConfig'@, then use
@'Crypto.Network.Noise.pipeServerStream'@, given an
@'System.IO.Streams.InputStream'@ and
@'System.IO.Streams.OutputStream'@:

@
(decryptedInput, encryptedOut) <- 'Crypto.Network.Noise.pipeServerStream' 'Crypto.Network.Noise.defaultPipeConfig' (in, out)
@

Given the two streams @in@ and @out@,
@'Crypto.Network.Noise.pipeServerStream'@ returns two streams which
when read from\/written to, encrypt\/decrypt the specified data, and
write it to the original streams. In other words,
@'Crypto.Network.Noise.pipeServerStream'@ transforms streams which
take encrypted data and turns them into streams which take unencrypted
data.

Note that every individual value which you @'System.IO.Streams.write'@
down the @'System.IO.Streams.OutputStream'@, an individual message is
created and written for it.

For example, with the above combinator, you can turn a
@'Network.Socket.Socket'@ into an encrypted set of streams using
@'System.IO.Streams.Network.socketToStreams'@:

@
createEncServerSocket :: 'Network.Socket.Socket' -> 'Crypto.Network.Noise.PipeConfig' -> IO ('System.IO.Streams.InputStream', 'System.IO.Streams.OutputStream')
createEncServerSocket socket conf
  -- \'socket\' is the listening socket of a server.
  (in, out) \<- ('System.IO.Streams.Network.socketToStreams' >=> 'Crypto.Network.Noise.pipeServerStream' conf) socket
  return (in, out)
@

Now any ingoing/outgoing traffic is transparently encrypted.

Now we can do the same with a client pipe, in the other direction:

@
createEncClientSocket :: 'Network.Socket.Socket' -> 'Crypto.Network.Noise.PipeConfig' -> IO ('System.IO.Streams.InputStream', 'System.IO.Streams.OutputStream')
createEncClientSocket socket conf
  -- \'socket\' is the socket connected to the server
  (in, out) \<- ('System.IO.Streams.Network.socketToStreams' >=> 'Crypto.Network.Noise.pipeClientStream' conf) socket
  return (in, out)
@

With these two combinators, we can turn any already connected sockets
into encrypted tunnels. This is very close to how the Network API in
this package is implemented, in fact.

Once you have the underlying streams, you can also naturally layer in
other streams. For example, to layer in a compression stream:

@
zlibStreams :: Int -- ^ Compression level
            -> ('System.IO.Streams.InputStream' 'Data.ByteString.ByteString', 'System.IO.Streams.OutputStream' 'Data.ByteString.ByteString')
            -> IO ('System.IO.Streams.InputStream' 'Data.ByteString.ByteString', 'System.IO.Streams.OutputStream' 'Data.ByteString.ByteString')
zlibStreams l (input, output)
  = (,) \<$\> 'System.IO.Streams.Zlib.decompress' input
        \<*\> 'System.IO.Streams.Zlib.compress' ('System.IO.Streams.Zlib.CompressionLevel' l) output

-- Create an tunnel where any data is first compressed, then encrypted.
createZlibEncServerSocket :: 'Network.Socket.Socket' -> 'Crypto.Network.Noise.PipeConfig' -> IO ('System.IO.Streams.InputStream', 'System.IO.Streams.OutputStream')
createZlibEncServerSocket socket config = do
  -- \'socket\' is the listening socket of a server.
  (in, out) \<- ('System.IO.Streams.Network.socketToStreams' >=> 'Crypto.Network.Noise.pipeServerStream' conf >=> zlibStreams 5) socket
  return (in, out)
@

In the above example, the socket is first turned into two streams, and
then into an encrypted tunnel. Then, the @'zlibStreams'@ function
tranforms it so that any data is first compressed before encryption.
After this, you can layer in any amount of other transformations you
want: for example, your own networking protocol, or simply
@'System.IO.Streams.connect'@ing the streams.

Note that when using pipes, the negotiation over the streams happens
immediately: any waiting will cause the thread issuing the handshake
to block, so if you want to handle this without waiting, be sure to
use a timeout or the \'async\' package.

Additionally, once you make a connection with
@'Crypto.Network.Noise.connect'@ or @'Crypto.Network.Noise.serve'@,
you can pull out the @'System.IO.Streams.InputStream'@ and
@'System.IO.Streams.OutputStream'@ to compose or transform it like
above, using @'Crypto.Network.Noise.pipeContextStreams'@.

-}

{- $padding

All messages in a noise pipe may optionally be padded to help prevent
plaintext length analysis on the encrypted pipe. By default, boxes
offer no padding - while pipes offer a small amount of random
padding, but /only/ in the initial negotiation phase!

To control the amount of padding set in a Noise box, use the input
parameter to @'Crypto.Encrypt.Noise.seal'@:

@
pad <- generateRandomNumberBetween 0 512
b <- 'Crypto.Encrypt.Noise.seal' Nothing receiver pad msg
...
@

This will encrypt the box and pad it with a random amount of data
(between 0 and 512 bytes, assuming a good distribution for the number
generator).

To pad the initial boxes that are exchanged in a Pipe handshake,
you can set the @'Crypto.Network.Noise.confPadding'@ parameter of the
@'Crypto.Network.Noise.PipeConf'@. For example, setting
@'Crypto.Network.Noise.confPadding' = 32@ will pad the initial
handshake message you send with 32 random bytes.

Encrypting an active Noise pipe is a little more work. In essence, you
must write a function to transform an
@'System.IO.Streams.OutputStream'@ of this type:

@
f :: 'System.IO.Streams.OutputStream' 'Crypto.Network.Noise.PipeMsg' -> IO ('System.IO.Streams.OutputStream' 'Data.ByteString.ByteString')
@

There is an alias for this type - @'Crypto.Network.Noise.PipeMsgPadder'@.

The type @'Crypto.Network.Noise.PipeMsg'@ is a simple message type,
pairing a @'Data.ByteString.ByteString'@ with an integer - the number
of bytes to pad the message containing that buffer. You can think of
@'System.IO.Streams.OutputStream' 'Crypto.Network.Noise.PipeMsg'@ as
being equivalent to @'System.IO.Streams.OutputStream'
('Data.ByteString.ByteString', Int)@

The simplest transformation is
@'Crypto.Network.Noise.constantPadStream'@, which pads every message
with a constant number of random bytes. This is used internally by
default if you don't specify your own transformation:

@
'Crypto.Network.Noise.constantPadStream' :: Word32 -> 'Crypto.Network.Noise.PipeMsgPadder'
'Crypto.Network.Noise.constantPadStream' n inp = 'System.IO.Streams.makeOutputStream' $ \\v ->
  case v of
    Nothing -> 'System.IO.Streams.write' Nothing inp
    Just x  -> 'System.IO.Streams.write' (Just ('Crypto.Network.Noise.PipeMsg' x n)) inp
@

For example, @'Crypto.Network.Noise.constantPadStream' 0@ is a routine
which will never pad any outgoing
messages.@'Crypto.Network.Noise.constantPadStream' 32@ is a routine
which will pad every message with 32 random bytes.

By default, a Noise pipe uses
@'Crypto.Network.Noise.constantPadStream' 0@ internally when you do
not specify your own padding routine.

In addition, there is also another routine provided -
@'Crypto.Network.Noise.randomPadStream'@ - which will pad every
outgoing message with a randomly selected number of bytes (within the
specified range).

Either end of a noise pipe can have their own unique padding routines
specified without problem.

To specify the padding routine, simply specify it in the
@'Crypto.Network.Noise.confPadder'@ of your configuration. For
example, to pad every message from the client with a random number of
bytes in the range of 0 to 32, and pad every message from the server
with 64 random bytes, you can write:

@
let sconf = 'Crypto.Network.Noise.defaultPipeConfig'
              { 'Crypto.Network.Noise.confPadder' = Just ('Crypto.Network.Noise.constantPadStream' 64)
              }

let cconf = 'Crypto.Network.Noise.defaultPipeConfig'
              { 'Crypto.Network.Noise.confPadder' = Just ('Crypto.Network.Noise.randomPadStream' 0 32)
              }
@

Note that padding is, of course, not free: as the bytes are taken from
@\/dev\/urandom@, in some very unscientific benchmarks, a parameter
like @('Crypto.Network.Noise.randomPadStream' 0 4096)@ cut the speed
of encrypting\/decrypting @\/dev\/zero@ and writing it to @/dev\/null@
by 50% (200MB\/s vs 100MB\/s), with the Linux kernel's internal
cryptographic routines dominating runtime profiles.

-}

{- $initial-msgs

Noise pipes have an advantage over TLS in that only one round trip is
needed to start sending data - as part of the handshake, the server
and client can exchange data inside boxes.

By default, servers and clients are configured to send 16 bytes of
zeros in their boxes, and they both validate the boxes have zeros in
the handshake. This can be changed by updating
@'Crypto.Network.Noise.PipeConfig'@ before connecting.

This feature allows you to immediately exchange data (taking full
advantage of the early roundtrip for your application), or do more
exotic things like certificate validation (see below for X509
support).

Using this support is easy. In the @'Crypto.Network.Noise.PipeConfig'@
for both parties, you can specify two fields:

@
 1 - 'Crypto.Network.Noise.confInitialMsg'      :: Maybe (IO 'Data.ByteString.ByteString')
 2 - 'Crypto.Network.Noise.confInitialResponse' :: Maybe ('Data.ByteString.ByteString' -> IO Bool)
@

These two fields specify the initial handshake procedure (in the
order they occur). By default, the handshake looks like:

@
Step #1: Client ---- Ephemeral Key ---> Server (BEGIN)

Step #2: Client <--- noise_box #1  ---- Server (Initial server message)

Step #3: Client ---- noise_box #2  ---> Server (Initial client message)

Step #4: Client \<---- ciphertext -----\> Server (Bidirectional communication)
@

The initial server message in step #2 is specified with
@'Crypto.Network.Noise.confInitialMsg'@ on the server end, and the
client checks if this is valid using
@'Crypto.Network.Noise.confInitialResponse'@. If it is, the client
responds with the result of its own
@'Crypto.Network.Noise.confInitialMsg'@ in step #3, and the server
checks this message with its
@'Crypto.Network.Noise.confInitialResponse'@. If this finishes, then
the connection is established in step #4 (see "Crypto.Noise.Protocol"
for details).

Note that even if these parameters are set to @'Nothing'@, validation
always takes place: if you /do not/ specify any override, or use
@'Nothing'@ explicitly, then the server uses the implicit default: a
payload of 16 zero bytes each way, with the validation confirming
this.

This means that if you override one of the initial messages, you MUST
override the counterpart for the other party. This prevents clients
and servers from finishing the handshake if they're incorrectly
configured on either end. In other words, this is the default
operation if you don't specify your own overrides:

@
'Crypto.Network.Noise.confInitialMsg'      = Just $ return ('Data.ByteString.replicate' 16 0x0)
'Crypto.Network.Noise.confInitialResponse' = Just $ \x -> return (x == 'Data.ByteString.replicate' 16 0x0)
@

-}

{- $x509

While public keys are powerful and small, many times they are not
convenient. There is sometimes a need for an outside authority to
verify integrity - in /some/ cases, it's often far more convenient to
have an authority sign certificates of authenticity for an endpoint,
instead of distributing multiple public keys for each endpoint to all
clients.

Like mentioned above, Noise pipe authentication is also flexible - as
both ends of a pipe can be anonymous, it's possible to use different
authentication mechanisms to establish secure connections.

To this end, this package features simple, built in X509 validation
using the one-roundtrip initial box discussed previously. This can be
used to verify a server presenting a certificate to a client is signed
by a trusted CA in the users Certificate Store.

The default routines use the system certificate store. To enable the
certificate, specify the @'Crypto.Network.Noise.offerX509'@ in the
@'Crypto.Network.Noise.PipeConfig'@.

@
> let sconf = 'Crypto.Network.Noise.defaultPipeConfig' { 'Crypto.Network.Noise.confInitialMsg' = Just ('Crypto.Network.Noise.offerX509' "noise.crt") }
@

where @"noise.crt"@ is your certificate, signed by someone in the
trusted store.

Next, make sure your client uses @'Crypto.Network.Noise.validateX509'@
in its @'Crypto.Network.Noise.PipeConfig'@:

@
> let cconf = 'Crypto.Network.Noise.defaultPipeConfig' { 'Crypto.Network.Noise.confInitialResponse' = Just $ 'Crypto.Network.Noise.validateX509' (Just \"HOSTNAME\") }
@

where @\"HOSTNAME\"@ is the FQDN specified in the certificate.

That's it. Your client will automatically check the X509 certificate
chain when they connect, and they'll reject invalid server
certificates. This can also work the other way around: servers can
validate client certificates too. Combined with anonymous ends, This
allows you to easily use different authentication methods as opposed
to public key distribution for Noise pipes.

You can also exercise more control over the validation check, using
the more extensive @'Crypto.Network.Noise.validateX509_'@
function. For example, when testing, it's often useful to use a
self-signed certificate. You can do this quite easily by using your
own X509 @'Data.X509.Validation.ValidationCache'@. First, create a
fingerprint of your self-signed certificate:

@
$ openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 -out noise.crt
...
$ openssl x509 -noout -sha256 -in noise.crt -fingerprint
SHA256 Fingerprint=\<YOUR_FINGERPRINT\>
@

(where @\<YOUR_FINGERPRINT\>@ is the SHA256 fingerprint of your
certificate).

Next, set up your @'Crypto.Network.Noise.ClientConfig'@ to use the
@'Network.X509.Validation.exceptionValidationCache'@, specifying the
service identifier and the fingerprint:

@
> let fp1 = Fingerprint $ B8.pack \"YOUR_FINGERPRINT\"
      validCache = exceptionValidationCache
        [ ((\"YOUR-FQDN\", B.empty), fp1)
        ]

      cconf = 'Crypto.Network.Noise.defaultPipeConfig' { 'Crypto.Network.Noise.confInitialResponse' = Just $ @'Crypto.Network.Noise.validateX509_'@ (Just \"HOSTNAME\") (Just validCache) Nothing }
@

Done! Now your clients will have an exception only for this
fingerprint and no other self-signed certificate will
work. Alternatively, using
@'Network.X509.Validation.tofuValidationCache'@ you can perform
\"Trust On First Use\" (/TOFU/) validation as well, making Noise
negotiations even more flexible.

Alternatively, you /can/ override the failure check for the validation
procedure. For example, if you want to accept /any/ self-signed
certificate (WHICH IS A BAD IDEA, MIND YOU):

@
> let selfSigned x = return (x == [] || x == [SelfSigned])
      cconf = 'Crypto.Network.Noise.defaultPipeConfig' { 'Crypto.Network.Noise.confInitialResponse' = Just $ @'Crypto.Network.Noise.validateX509_'@ (Just \"HOSTNAME\") Nothing (Just selfSigned) }
@

This new configuration overrides the failure check: if there are no
errors OR the certificate fails only due to self-signing, then the
certificate is accepted.

-}

{- $differences

Currently, this package /mostly/ implements the Noise specification
faithfully.

The large exception is that we use Curve25519 instead of
Curve41417. Curve41417 offers a 200-bit security level, which is
really what Noise aims to offer (NaCl @crypto_box@ routines similarly
only offer 128-bit security). As a result, keys are only 32 bytes as
opposed to 52 bytes.

In the future, this protocol will use Curve41417 by default.

-}

{- $othernotes

Here are some important things to note when using this protocol:

    [@You can't turn off the encryption@] There is no way to disable
encryption. Furthermore, the primitives should be high-speed enough to
not negatively impact large workloads.

    [@No protection against traffic analysis by default@] While the
initial boxes feature randomized padding by default, the outgoing
ciphertext is not padded in any way.. If you want to randomize your
traffic a bit, use the
@'Crypto.Network.Noise.randomPadStream'@ transformer in your
configuration to automatically pad outgoing traffic. The underlying
random number generator is MWC seeded from @\/dev\/urandom@, so it
should be fast, and pick numbers in the specified range with a good
distribution.

-}
