{-# LANGUAGE OverloadedStrings #-}

-- | Protocol description
--
-- Defines functions that handle the advancing of the Tor control protocol.
--
--   __Warning__: This function is used internally by 'Network.Anonymous.Tor'
--                and using these functions directly is unsupported. The
--                interface of these functions might change at any time without
--                prior notice.
--
module Network.Anonymous.Tor.Protocol ( NST.connect
                                      , detectPort
                                      , protocolInfo
                                      , authenticate ) where

import           Control.Concurrent.MVar

import           Control.Monad                             (when)
import           Control.Monad.Catch                       (handleAll)
import           Control.Monad.IO.Class

import qualified Data.Attoparsec.ByteString                as Atto
import qualified Data.ByteString                           as BS
import qualified Data.ByteString.Char8                     as BS8
import           Data.Maybe                                (catMaybes, fromJust)

import qualified Data.Text as T
import qualified Data.Text.Encoding as TE

import qualified Network.Attoparsec                        as NA
import qualified Network.Simple.TCP                        as NST

import qualified Network.Socket                            as Network hiding
                                                                       (recv,
                                                                       send)
import qualified Network.Socket.ByteString                 as Network

import qualified Network.Anonymous.Tor.Error               as E
import qualified Network.Anonymous.Tor.Protocol.Parser     as Parser
import qualified Network.Anonymous.Tor.Protocol.Parser.Ast as Ast
import qualified Network.Anonymous.Tor.Protocol.Types      as T

import           Debug.Trace                               (trace)

sendCommand :: MonadIO m
            => Network.Socket -- ^ Our connection with the Tor control port
            -> BS.ByteString  -- ^ The command / instruction we wish to send
            -> m Ast.Reply
sendCommand s m = do
  _ <- liftIO $ Network.sendAll s m
  liftIO $ NA.parseOne s (Atto.parse Parser.reply)

-- | Probes several default ports to see if there is a service at the remote
--   that behaves like the Tor controller daemon. Will return a list of all
--   the probed ports that have a Tor service, since in some scenarios there
--   will be multiple Tor services (specifically, when a user has both the
--   Tor browser bundle and a separate Tor relay running).
detectPort :: MonadIO m
           => [Integer]   -- ^ The ports we wish to probe
           -> m [Integer] -- ^ The ports which respond like a Tor service
detectPort possible = do

  ports <- liftIO $ mapM hasTor possible

  return (catMaybes ports)

  where
    -- Returns the port if the remote service is available and responds in
    -- an expected fashion to 'protocolInfo', returns Nothing otherwise.
    hasTor :: Integer -> IO (Maybe Integer)
    hasTor port = do
      result <- liftIO newEmptyMVar

      handleAll
        (\_ -> liftIO $ putMVar result Nothing)
        (NST.connect "127.0.0.1" (show port) (\(sock, _) -> do
                                                 info <- protocolInfo sock
                                                 liftIO $ putStrLn ("protocolInfo = " ++ show info)
                                                 liftIO $ putMVar result (Just port)))

      liftIO $ takeMVar result

-- | Requests protocol version information from Tor. This can be used while
--   still unauthenticated and authentication methods can be derived from this
--   information.
protocolInfo :: MonadIO m
             => Network.Socket
             -> m T.ProtocolInfo
protocolInfo s = do
  Ast.Reply res <- sendCommand s (BS.concat ["PROTOCOLINFO", "\n"])

  when
    (Ast.statusCode res /= 250)
    (E.torError (E.mkTorError E.protocolErrorType))

  return (T.ProtocolInfo (protocolVersion res) (torVersion res) (methods res) (cookieFile res))

  where

    protocolVersion :: [Ast.Line] -> Integer
    protocolVersion reply =
      fst . fromJust . BS8.readInteger . Ast.tokenKey . last . Ast.lineMessage . fromJust $ Ast.line (BS8.pack "PROTOCOLINFO") reply

    torVersion :: [Ast.Line] -> [Integer]
    torVersion reply =
      map (fst . fromJust . BS8.readInteger) . BS8.split '.' . fromJust . Ast.value "Tor" . Ast.lineMessage . fromJust $ Ast.line (BS8.pack "VERSION") reply

    methods :: [Ast.Line] -> [T.AuthMethod]
    methods reply =
      map (read . BS8.unpack) . BS8.split ',' . fromJust . Ast.value "METHODS" . Ast.lineMessage . fromJust $ Ast.line (BS8.pack "AUTH") reply

    cookieFile :: [Ast.Line] -> Maybe T.Text
    cookieFile reply =
      fmap TE.decodeUtf8 . Ast.value "COOKIEFILE" . Ast.lineMessage . fromJust $ Ast.line (BS8.pack "AUTH") reply

-- | Authenticates with the Tor control server, based on the authentication
--   information returned by PROTOCOLINFO.
authenticate :: MonadIO m
             => Network.Socket
             -> m ()
authenticate s = do
  info <- protocolInfo s

  trace ("info = " ++ show info) (return ())

  return ()
