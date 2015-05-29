{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE FlexibleContexts #-}

-- | This module provides the main interface for establishing secure and
--   anonymous connections with other hosts on the interface using the
--   Tor project. For more information about the Tor network, see:
--   <https://www.torproject.org/ torproject.org>
--
module Network.Anonymous.Tor (
  -- * Introduction to Tor
  -- $tor-introduction

  -- * Client side
  -- $tor-client
    P.connect
  , P.connect'

  -- * Server side
  -- $tor-server
  , P.mapOnion
  , accept

  -- * Probing Tor configuration information
  , P.detectPort
  , P.socksPort

  -- ** Setting up the context
  , withSession

  ) where

import           Control.Concurrent                      (forkIO)
import           Control.Concurrent.MVar
import           Control.Monad                           (forever)
import           Control.Monad.Catch
import           Control.Monad.IO.Class

import qualified Data.Base32String.Default                 as B32
import qualified Data.ByteString                         as BS

import qualified Network.Simple.TCP                        as NST
import qualified Network.Socket                          as Network

import qualified Network.Anonymous.Tor.Protocol          as P


--------------------------------------------------------------------------------
-- $tor-introduction
--
-- This module is a (partial) implementation of the Tor control protocol. Tor is an
-- internet anonimization network. Whereas historically, Tor is primarily
-- intended for privately browsing the world wide web, the service also supports
-- application oriented P2P communication, to implement communication between applications.
--
-- The general idea of the Tor control interface to Tor is that you establish a master
-- connection with the Tor control port, and create new, short-lived connections with
-- the Tor bridge for the communication with the individual peers.
--
--------------------------------------------------------------------------------
-- $tor-client
--
-- == Virtual Stream
-- Establishing a 'S.VirtualStream' connection with a remote works as follows:
--
-- @
--   main = 'withSession' 'defaultEndPoint' 'S.VirtualStream' withinSession
--
--   where
--     dest :: 'D.PublicDestination'
--     dest = undefined
--
--     withinSession :: 'S.Context' -> IO ()
--     withinSession ctx =
--       'connectStream' ctx dest worker
--
--     worker (sock, addr) = do
--       -- Now you may use sock to communicate with the remote; addr contains
--       -- the address of the remote we are connected to, which on our case
--       -- should match dest.
--       return ()
-- @
--
-- == Datagram
-- Sending a 'S.DatagramRepliable' message to a remote:
--
-- @
--   main = 'withSession' 'defaultEndPoint' 'S.DatagramRepliable' withinSession
--
--   where
--     dest :: 'D.PublicDestination'
--     dest = undefined
--
--     withinSession :: 'S.Context' -> IO ()
--     withinSession ctx = do
--       'sendDatagram' ctx dest \"Hello, anonymous world!\"
--
--       -- SAM requires the master connection of a session to be alive longer
--       -- than any opertions that occur on the session are. Since sending a
--       -- datagram returns before the datagram might be actually handled by
--       -- Tor, it is adviced to wait a little while before closing the session.
--       threadDelay 1000000
-- @
--
--------------------------------------------------------------------------------
-- $tor-server
--
-- == Virtual Stream
-- Running a server that accepts 'S.VirtualStream' connections.
--
-- @
--   main = 'withSession' 'defaultEndPoint' 'S.VirtualStream' withinSession
--
--   where
--     withinSession :: 'S.Context' -> IO ()
--     withinSession ctx =
--       'serveStream' ctx worker
--
--     worker (sock, addr) = do
--       -- Now you may use sock to communicate with the remote; addr contains
--       -- the address of the remote we are connected to, which we might want
--       -- to store to send back messages asynchronously.
--       return ()
-- @
--
-- == Datagram
-- Receiving 'S.DatagramAnonymous' messages from remotes:
--
-- @
--   main = 'withSession' 'defaultEndPoint' 'S.DatagramAnonymous' withinSession
--
--   where
--     withinSession :: 'S.Context' -> IO ()
--     withinSession ctx =
--       'serveDatagram' ctx worker
--
--     worker (sock, addr) = do
--       -- Now you may use sock to communicate with the remote; addr is an
--       -- instance of the 'Maybe' monad, and since we only accept anonymous
--       -- messages, should always be 'Nothing'.
--       return ()
-- @
--------------------------------------------------------------------------------

-- | Establishes a connection and authenticates with the Tor control socket.
--   After authorization has been succesfully completed it executes the callback
--   provided.
--
--   Note that when the session completes, the connection with the Tor control
--   port is dropped, which means that any port mappings, connections and hidden
--   services you have registered within the session will be cleaned up. This
--   is by design, to prevent stale mappings when an application crashes.
withSession :: Integer                  -- | Port the Tor control server is listening at. Use
                                        --   'detectPort' to probe possible ports.
            -> (Network.Socket -> IO a) -- | Callback function called after a session has been
                                        --   established succesfully.
            -> IO a                     -- | Returns the value returned by the callback.
withSession port callback =
  NST.connect "127.0.0.1" (show port) (\(sock, _) -> do
                                            _ <- P.authenticate sock
                                            callback sock)

-- | Convenience function that creates a new hidden service and starts accepting
--   connections for it. Note that this creates a new local server at the same
--   port as the public port, so ensure that the port is not yet in use.
accept :: MonadIO m
       => Network.Socket            -- | Connection with Tor control server
       -> Integer                   -- | Port to listen at
       -> (Network.Socket -> IO ()) -- | Callback function called for each incoming connection
       -> m B32.Base32String        -- | Returns the hidden service descriptor created
                                    --   without the '.onion' part.
accept sock port callback = do
  -- First create local service
  _ <- liftIO $ forkIO $
       NST.listen "*" (show port) (\(lsock, _) -> NST.accept lsock (\(sock, _) -> callback sock))

  P.mapOnion sock port port
