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

spec :: Spec
spec = return ()
