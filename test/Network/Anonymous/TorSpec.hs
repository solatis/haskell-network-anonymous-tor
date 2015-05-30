{-# LANGUAGE OverloadedStrings #-}

module Network.Anonymous.TorSpec where

import           Control.Concurrent                   (ThreadId, forkIO,
                                                       killThread, threadDelay)
import           Control.Concurrent.MVar
import           Control.Monad.Catch
import           Control.Monad.IO.Class

import qualified Network.Socket                       as NS (Socket)
import qualified Network.Socket.ByteString            as NSB (recv, sendAll)

import qualified Network.Anonymous.Tor.Error          as E
import qualified Network.Anonymous.Tor                as Tor
import qualified Network.Anonymous.Tor.Protocol.Types as PT
import qualified Network.Socks5.Types                 as SocksT

import qualified Data.Base32String.Default            as B32
import qualified Data.ByteString                      as BS
import qualified Data.ByteString.Char8                as BS8
import qualified Data.Text                            as T
import qualified Data.Text.Encoding                   as TE


import           Data.Maybe                           (fromJust, isJust,
                                                       isNothing)

import           Test.Hspec

whichPort :: IO Integer
whichPort = do
  ports <- Tor.detectPort [9051, 9151]
  return (head ports)

spec :: Spec
spec = do
  describe "when starting a new server" $ do
    it "should accept connections through a hidden server" $ do
      clientDone <- newEmptyMVar
      serverDone <- newEmptyMVar

      port <- whichPort
      Tor.withSession port (withinSession clientDone serverDone)

      takeMVar clientDone `shouldReturn` True
      takeMVar serverDone `shouldReturn` True

      where
        withinSession clientDone serverDone sock = do
          onion <- Tor.accept sock 4321 (serverWorker serverDone)

          putStrLn ("Got Tor hidden server: " ++ show onion)
          putStrLn ("waiting 30 seconds..")
          threadDelay 30000000
          putStrLn ("waited 30 seconds, connecting..")

          Tor.connect' sock (constructDestination onion 4321) (clientWorker clientDone)

        destinationAddress onion =
          TE.encodeUtf8 $ T.concat [B32.toText onion, T.pack ".ONION"]

        constructDestination onion port =
            SocksT.SocksAddress (SocksT.SocksAddrDomainName (destinationAddress onion)) port

        serverWorker serverDone sock = do
          putStrLn "Accepted connection"
          putMVar serverDone True

        clientWorker clientDone sock = do
          putStrLn "Connected to hidden service!"
          putMVar clientDone True
