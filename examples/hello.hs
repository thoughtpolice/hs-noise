{-# LANGUAGE OverloadedStrings #-}
import Network.Noise
import Control.Concurrent
import qualified Data.ByteString.Char8 as B8

main :: IO ()
main = do
  send1@(sendPK, sendSK) <- createKeypair
  recv1@(recvPK, recvSK) <- createKeypair

  -- Test #1
  bs <- box (Just send1) recvPK 32 (B8.pack "Hello world!")
  print $ open recvSK (Just sendPK) bs

  -- Test #2
  bs <- box Nothing recvPK 32 (B8.pack "Goodbye world!")
  print $ open recvSK Nothing bs

  -- Test #3
  server@(serverPK,_) <- createKeypair
  client@(clientPK,_) <- createKeypair

  let sconf = ServerConfig 32 Nothing Nothing
  forkIO $ serve (Host "127.0.0.1") "8234" sconf $ \(ctx, remoteAddr) -> do
    putStrLn $ "[s] TCP connection established from " ++ show remoteAddr
    send ctx 28 (B8.pack "Hello world!")
    msg <- recv ctx
    threadDelay (1*1000*1000)
    putStrLn $ "[s] Got message: " ++ maybe "Nothing" B8.unpack msg

  threadDelay (1*1000*1000)
  let cconf = ClientConfig 32 Nothing Nothing
  connect "127.0.0.1" "8234" cconf $ \(ctx, remoteAddr) -> do
    threadDelay (1*1000*1000)
    putStrLn $ "[c] Connection established to " ++ show remoteAddr
    msg <- recv ctx
    threadDelay (1*1000*1000)
    putStrLn $ "[c] Got message: " ++ maybe "Nothing" B8.unpack msg
    send ctx 84 (B8.pack "Goodbye world!")
    threadDelay (5*1000*1000)
