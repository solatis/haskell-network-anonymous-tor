{-# LANGUAGE OverloadedStrings #-}

module Network.Anonymous.TorSpec where

import           Control.Concurrent                   (threadDelay)
import           Control.Concurrent.MVar

import qualified Network.Anonymous.Tor                as Tor
import qualified Network.Socks5.Types                 as SocksT

import qualified Data.Base32String.Default            as B32
import qualified Data.Text                            as T
import qualified Data.Text.Encoding                   as TE

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

        serverWorker serverDone _ = do
          putStrLn "Accepted connection"
          putMVar serverDone True

        clientWorker clientDone _ = do
          putStrLn "Connected to hidden service!"
          putMVar clientDone True
