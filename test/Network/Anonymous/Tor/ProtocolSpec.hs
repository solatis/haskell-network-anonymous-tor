{-# LANGUAGE OverloadedStrings #-}

module Network.Anonymous.Tor.ProtocolSpec where

import           Control.Concurrent                      (ThreadId, forkIO,
                                                          killThread,
                                                          threadDelay)
import           Control.Concurrent.MVar
import           Control.Monad.Catch
import           Control.Monad.IO.Class

import qualified Network.Simple.TCP                      as NS (accept, listen,
                                                                send)
import qualified Network.Socket                          as NS (Socket)
import qualified Network.Socket.ByteString               as NSB (recv, sendAll)

import qualified Network.Anonymous.Tor.Error             as E
import qualified Network.Anonymous.Tor.Util              as U
import qualified Network.Anonymous.Tor.Protocol          as P
import qualified Network.Anonymous.Tor.Protocol.Types    as PT

import qualified Data.ByteString                         as BS
import qualified Data.ByteString.Char8                   as BS8
import           Data.Maybe                              (fromJust, isJust,
                                                          isNothing)

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
  ports <- P.detectPort [9051, 9151]
  return (head ports)

connect :: (NS.Socket -> IO a) -> IO a
connect callback = do
  port <- whichPort
  P.connect "127.0.0.1" (show port) (\(sock, _) -> callback sock)

spec :: Spec
spec = do
  describe "when detecting a Tor control port" $ do
    it "should detect a port" $ do
      ports <- P.detectPort [9051, 9151]
      (length ports) `shouldBe` 1

  describe "when detecting protocol info" $ do
    it "should allow cookie authentication" $ do
      info <- connect P.protocolInfo
      (PT.authMethods info) `shouldSatisfy` (elem PT.Cookie)
