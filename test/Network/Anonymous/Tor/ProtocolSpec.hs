{-# LANGUAGE OverloadedStrings #-}

module Network.Anonymous.Tor.ProtocolSpec where

import           Control.Concurrent                   (ThreadId, forkIO,
                                                       killThread, threadDelay)
import           Control.Concurrent.MVar
import           Control.Monad.Catch
import           Control.Monad.IO.Class

import           Data.List                            (intersect)

import qualified Network.Simple.TCP                   as NS (accept, connect,
                                                             listen, send)
import qualified Network.Socket                       as NS (Socket)

import qualified Network.Anonymous.Tor.Protocol       as P
import qualified Network.Anonymous.Tor.Protocol.Types as PT
import qualified Network.Socks5.Types                 as SocksT

import qualified Data.Base32String.Default            as B32
import qualified Data.ByteString.Char8                as BS8
import qualified Data.Text                            as T
import qualified Data.Text.Encoding                   as TE

import           Test.Hspec

mockServer :: ( MonadIO m
              , MonadMask m)
           => String
           -> (NS.Socket -> IO a)
           -> m ThreadId
mockServer port callback = do
  tid <- liftIO $ forkIO $
    NS.listen "*" port (\(lsock, _) -> NS.accept lsock (\(sock, _) -> do
                                                           _ <- callback sock
                                                           threadDelay 1000000
                                                           return ()))

  liftIO $ threadDelay 500000
  return tid

whichPort :: IO Integer
whichPort = do
  let ports = [9051, 9151]
  availability <- mapM P.isAvailable ports
  return . fst . head . filter ((== P.Available) . snd) $ zip ports availability

connect :: (NS.Socket -> IO a) -> IO a
connect callback = do
  port <- whichPort
  NS.connect "127.0.0.1" (show port) (\(sock, _) -> callback sock)

spec :: Spec
spec = do
  describe "when detecting a Tor control port" $ do
    it "should detect a port" $ do
      port <- whichPort
      port `shouldSatisfy` (> 1024)

  describe "when detecting protocol info" $ do
    it "should allow cookie or null authentication" $ do
      info <- connect P.protocolInfo
      (PT.authMethods info) `shouldSatisfy`
        (not . null . intersect [PT.Cookie, PT.Null])

  describe "when authenticating with Tor" $ do
    it "should succeed" $ do
      _ <- connect P.authenticate
      True `shouldBe` True

  describe "when detecting SOCKS port" $ do
    it "should return a valid port" $ do
      port <- connect $ \sock -> do
        P.authenticate sock
        P.socksPort sock

      port `shouldSatisfy` (> 1024)

  describe "when connecting through a SOCKS port" $ do
    it "should be able to connect to google" $
      let clientSock done _ =
            putMVar done True

          constructSocksDestination =
            SocksT.SocksAddress (SocksT.SocksAddrDomainName (BS8.pack "www.google.com")) 80

      in do
        done <- newEmptyMVar

        _ <- connect $ \controlSock -> do
          P.authenticate controlSock
          P.connect' controlSock constructSocksDestination (clientSock done)

        takeMVar done `shouldReturn` True

  describe "when mapping an onion address v2" $ do
    it "should succeed in creating a mapping" $
      let serverSock sock = do
            putStrLn "got client connecting to hidden service!"
            NS.send sock "HELLO\n"
          clientSock _ =
            putStrLn "Got a connection with hidden service!"

          destinationAddress onion =
            TE.encodeUtf8 $ T.concat [B32.toText onion, T.pack ".ONION"]

          constructSocksDestination onion =
            SocksT.SocksAddress (SocksT.SocksAddrDomainName (destinationAddress onion)) 80

      in do
        thread <- liftIO $ mockServer "8080" serverSock

        _ <- connect $ \controlSock -> do
          P.authenticate controlSock
          addr <- P.mapOnion controlSock 80 8080 False Nothing

          putStrLn ("got onion address: " ++ show addr)
          putStrLn ("waiting 1 minute..")

          threadDelay 60000000

          putStrLn ("waited 1 minute, connecting..")

          P.connect' controlSock (constructSocksDestination addr) clientSock

        killThread thread

  describe "when mapping an onion address v3" $ do
    it "should succeed in creating a mapping" $
      let serverSock sock = do
            putStrLn "got client connecting to hidden service!"
            NS.send sock "HELLO\n"
          clientSock _ =
            putStrLn "Got a connection with hidden service!"

          destinationAddress onion =
            TE.encodeUtf8 $ T.concat [B32.toText onion, T.pack ".ONION"]

          constructSocksDestination onion =
            SocksT.SocksAddress (SocksT.SocksAddrDomainName (destinationAddress onion)) 80

      in do
        thread <- liftIO $ mockServer "8080" serverSock

        _ <- connect $ \controlSock -> do
          P.authenticate controlSock
          addr <- P.mapOnionV3 controlSock 80 8080 False Nothing

          putStrLn ("got onion address: " ++ show addr)
          putStrLn ("waiting 1 minute..")

          threadDelay 60000000

          putStrLn ("waited 1 minute, connecting..")

          P.connect' controlSock (constructSocksDestination addr) clientSock
        killThread thread
