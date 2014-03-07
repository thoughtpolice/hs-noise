-- |
-- Module      : Crypto.Noise.Protocol
-- Copyright   : (c) Austin Seipp 2014
-- License     : MIT
--
-- Maintainer  : aseipp@pobox.com
-- Stability   : experimental
-- Portability : portable
--
-- This module describes the Noise implementation given in this
-- library. The official protocol format can be found
-- <https://github.com/trevp/noise/wiki/ here>.
--
module Crypto.Noise.Protocol
       ( -- * Introduction
         -- $introduction

         -- * Connection overview
         -- $connection

         -- ** Minute-keys
         -- $minutekeys

         -- * Wire format
         -- $wireformat

         -- * Congestion avoidance: Chicago
         -- $chicago

         -- * Differences from the reference code
         -- $differences
       ) where

{- $introduction

A CurveCP connection begins life with a @HELLO@ packet from a client,
a @COOKIE@ packet from the server, and finally an @INITIATE@ packet
from the client. An @INITIATE@ packet may contain application
data. Afterwords, the server is free to send any number of Message
packets after a valid @INITIATE@. The client may send any number of
message packets after the first Message from the server.

If a client doesn't see a @COOKIE@ packet, it will send another
@HELLO@. Similarly, a client may send multiple @INITIATE@ packets if
it does not see a Message.

[@Notation@]

  * @S@  : Server long-term public key

  * @s@  : Server long-term secret key

  * @S'@ : Server short-term public key

  * @s'@ : Server short-term secret key

  * @C@ : Client long-term public key

  * @c@ : Client long-term secret key

  * @C'@ : Client short-term public key

  * @c'@ : Client short-term secret key

  * @t@ : Minute-key

  * @Z@ : All zeros.

  * @N@ : Server domain name

  * @...@ or @M@ : Message

  * @Box[X](C->S)@ : Encrypt-and-authenticate @X@ from the client's
public key @C@ to the server's public key @S@.

  * @V@ : Vouch packet - @Box[C'](C->S)@

  * @K@ : Cookie packet - @Box[C',s'](t)@
-}

{- $connection

The following diagram describes the lifetime of a CurveCP connection
from beginning to end. Note that @INITIATE@ packets may contain
application data: there are only two packets necessary for the client
to begin sending data, and three packets before the server may send
data.

@
             Client                                                 Server
+-------------------------------+                      +-------------------------------+
|    (C', 0, Box[Z](C'->S))     | ------ HELLO ------> |           Received            | Client sends HELLO
+-------------------------------+                      +-------------------------------+
                                                                      |
                                                                      v
+-------------------------------+                      +-------------------------------+
|           Received            | \<----- COOKIE ------ |       (Box[S',K](S->C'))      | Server sends COOKIE
+-------------------------------+                      +-------------------------------+
               |
               v
+-------------------------------+                      +-------------------------------+
| (C',K,Box[C,V,N,...](C'->S')) | ----- INITIATE ----> |           Received            | Client sends INITIATE
+-------------------------------+                      +-------------------------------+
                                                                      |
                                                                      v
+-------------------------------+                      +-------------------------------+
|           Received            | \<------ SMSG ------- |       (Box[...](S'->C'))      | Server sends Message
+-------------------------------+                      +-------------------------------+
               |
               v
+-------------------------------+                      +-------------------------------+
|    (C',Box[...](C'->S'))      | ------- CMSG ------> |            Received           | Client sends Message
+-------------------------------+                      +-------------------------------+
                                                                      |
                                                                      v
+-------------------------------+                      +-------------------------------+
|           Received            | \<------ SMSG ------- |       (Box[...](S'->C'))      | Server sends Message
+-------------------------------+                      +-------------------------------+
               |
               v
+-------------------------------+                      +-------------------------------+
|    (C',Box[...](C'->S'))      | ------- CMSG ------> |            Received           | Client sends Message
+-------------------------------+                      +-------------------------------+
                                                                      |
                                                                      v
                                                                     ...
@

-}


{- $wireformat

The following describes the wire format of all packets and messages.

In the following layouts, the notation @n : m : F@ means the field @F@
is located at offset @n@ and is @m@ bytes long. The notation @m:F@
(used inline) means @F@ is @m@ bytes long.

Note that the overhead of a @Box@ is 16 bytes: if @length(T) = x@ then
@length(Box[T](C->S)) = x+16@

    [/HELLO/] - 224 byte packet; Client -> Server

@
0   : 8  : magic, \"QvnQ5XlH\"
8   : 16 : server extension
24  : 16 : client extension
40  : 32 : C'
72  : 64 : Z
136 : 8  : compressed nonce
144 : 80 : Box[64:Z](C'->S)
@

    [/COOKIE/] - 200 byte packet; Server -> Client

@
0  : 8   : magic, \"RL3aNMXK\"
8  : 16  : client extension
24 : 16  : server extension
40 : 16  : compressed nonce
56 : 144 : Box[S',K](S->C') where:
            K = 0  : 16 : compressed cookie nonce
                16 : 80 : Box[C',s'](t)
@

    [/INITIATE/] - (544+M)-byte packet; Client -> Server

@
0   : 8     : magic, \"QvnQ5XlI\"
8   : 16    : server extension
24  : 16    : client extension
40  : 32    : C'
72  : 96    : cookie K, where:
               K = 0   : 16    : compressed cookie nonce
                   16  : 80    : Box[C',s'](t)
168 : 8     : compressed nonce
176 : 368+M : Box[X](C'->S') containing:
176 :          X = 0   : 32  : C client long-term public key
208 :              32  : 16  : compressed nonce
224 :              48  : 48  : Box[C'](C->S)
272 :              96  : 256 : N
528 :              352 : M   : M
@

    [/SMSG/] - (64+M)-byte packet

@
0  : 8    : magic, \"RL3aNMXM\"
8  : 16   : client extension
24 : 16   : server extension
40 : 8    : compressed nonce
48 : 16+M : Box[M](S'->C')
@

    [/CMSG/] - (96+M)-byte packet

@
0   : 8    : magic, \"QvnQ5XlM\"
8   : 16   : server extension
24  : 16   : client extension
40  : 32   : C'
72  : 8    : compressed nonce
80  : 16+M : Box[M](C'->S')
@

    [/Message format/]


-}

{- $minutekeys

The /minute key/ @t@ is a secret key for use only by the server, under
which a cookie @K@ is encrypted. As @K@ is encrypted to the client
inside a @COOKIE@ packet, it provides a means of validating the
authentic client has responded.

Once every minute, the server rotates the minute key @t@, while
retaining the prior key. Thus, at any given time, the server may
understand a cookie @K@ from the past two minutes.

When a server receives an
@INITIATE@ packet, it attempts to decrypt and validate @K@ with
respect to the current and prior minute keys.
-}

{- $chicago

/Chicago/ is the congestion avoidance scheduling algorithm used by
CurveCP.

-}

{- $differences

This module is not wire-format compatible with the original CurveCP
implementation, as written by Bernstein.

Notably, it takes the advice written
<http://codesinchaos.wordpress.com/2012/09/09/curvecp-1/ in this analysis> and
applies it. That is, the main differences are:

    [@Random Nonces@] The server always uses random nonces due to
negligable collision risk and the fragility of incrementing nonces.

    [@Stronger client authentication@] Lorem ipsum...

    [@Stopping INITIATE replays@] The server puts @C'@ on a blacklist
when initiating connections, so that attackers cannot replay a full
connection while the minute-key associated with the packet is
valid. Connections with an in-use short-term key are also prevented.
-}
