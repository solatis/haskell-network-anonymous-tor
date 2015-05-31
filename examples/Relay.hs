{-# LANGUAGE OverloadedStrings #-}

import           System.Environment    (getArgs)

import           Control.Concurrent    (threadDelay)
import           Network               (withSocketsDo)
import qualified Network.Anonymous.Tor as Tor
import qualified Network.Socks5.Types  as SocksT

getPortmap :: IO (Integer, Integer)
getPortmap = do
  [pub, priv] <- getArgs
  return (read pub, read priv)

whichControlPort :: IO Integer
whichControlPort = do
  ports <- Tor.detectPort [9051, 9151]
  return (head ports)

main = withSocketsDo $ do
  torPort <- whichControlPort
  portmap <- getPortmap

  Tor.withSession torPort (withinSession portmap)

  return ()

  where
    withinSession (publicPort, privatePort) controlSock = do
      onion <- Tor.accept controlSock publicPort (newConnection privatePort)

      putStrLn ("hidden service descriptor: " ++ show onion)

      -- If we would leave this function at this point, our connection with
      -- the Tor control service would be lost, which would cause Tor to clean
      -- up any mappings and hidden services we have registered.
      --
      -- Since this is just an example, we will now wait for 5 minutes and then
      -- exit.
      threadDelay 300000000

    newConnection privatePort sock = do
      putStrLn "Got new connection!"
      return ()
