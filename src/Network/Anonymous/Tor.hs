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
  , P.Availability (..)
  , P.isAvailable
  , P.socksPort

  -- ** Setting up the context
  , withSession

  ) where

import           Control.Concurrent                      (forkIO, threadDelay)
import           Control.Monad.IO.Class

import qualified Data.Base32String.Default                 as B32
import qualified Data.ByteString                           as BS

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
-- == Connect through Tor with explicit port
-- Connect through Tor on using a specified SOCKS port. Note that you do not
-- need to authorize with the Tor control port for this functionality.
--
-- @
--   main = 'connect' 9050 constructDestination worker
--
--   where
--     constructDestination =
--       'SocksT.SocksAddress' (SocksT.SocksAddrDomainName (BS8.pack "www.google.com")) 80
--
--     worker sock =
--       -- Now you may use sock to communicate with the remote.
--       return ()
-- @
--
-- == Connect through Tor using control port
-- Connect through Tor and derive the SOCKS port from the Tor configuration. This
-- function will query the Tor control service to find out which SOCKS port the
-- Tor daemon listens at.
--
-- @
--   main = 'withSession' withinSession
--
--   where
--     constructDestination =
--       'SocksT.SocksAddress' (SocksT.SocksAddrDomainName (BS8.pack "2a3b4c.onion")) 80
--
--     withinSession :: 'Network.Socket' -> IO ()
--     withinSession sock = do
--       'connect'' sock constructDestination worker
--
--     worker sock =
--       -- Now you may use sock to communicate with the remote.
--       return ()
-- @
--
--------------------------------------------------------------------------------
-- $tor-server
--
-- == Mapping
-- Create a new hidden service, and map remote port 80 to local port 8080.
--
-- @
--   main = 'withSession' withinSession
--
--   where
--     withinSession :: 'Network.Socket' -> IO ()
--     withinSession sock = do
--       onion <- 'mapOnion' sock 80 8080
--       -- At this point, 'onion' contains the base32 representation of
--       -- our hidden service, without the trailing '.onion' part.
--       --
--       -- Remember that, once we leave this function, the connection with
--       -- the Tor control service will be lost and any mappings will be
--       -- cleaned up.
-- @
--
-- == Server
-- Convenience function which creates a hidden service on port 80 that is mapped
-- to a server we create on the fly. Note that because we are mapping the hidden
-- service's port 1:1 with our local port, port 80 must still be available.
--
-- @
--   main = 'withSession' withinSession
--
--   where
--     withinSession :: 'Network.Socket' -> IO ()
--     withinSession sock = do
--       onion <- 'accept' sock 80 worker
--       -- At this point, 'onion' contains the base32 representation of
--       -- our hidden service, without the trailing '.onion' part, and any
--       -- incoming connections will be redirected to our 'worker' function.
--       --
--       -- Once again, when we leave this function, all registered mappings
--       -- will be lost.
--
--     worker sock = do
--       -- Now you may use sock to communicate with the remote.
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

withSession :: Integer                  -- ^ Port the Tor control server is listening at. Use
                                        --   'detectPort' to probe possible ports.
            -> (Network.Socket -> IO a) -- ^ Callback function called after a session has been
                                        --   established succesfully.
            -> IO a                     -- ^ Returns the value returned by the callback.
withSession port callback =
  NST.connect "127.0.0.1" (show port) (\(sock, _) -> do
                                            _ <- P.authenticate sock
                                            callback sock)

-- | Convenience function that creates a new hidden service and starts accepting
--   connections for it. Note that this creates a new local server at the same
--   port as the public port, so ensure that the port is not yet in use.
accept :: MonadIO m
       => Network.Socket                      -- ^ Connection with Tor control server
       -> Integer                             -- ^ Port to listen at
       -> Maybe BS.ByteString                 -- ^ Optional private key to use to set up the hidden service
       -> (Network.Socket -> IO ())           -- ^ Callback function called for each incoming connection
       -> m B32.Base32String -- ^ Returns the hidden service descriptor created without
                                              --   the '.onion' part
accept sock port pkey callback = do
  -- First create local service
  _ <- liftIO $ forkIO $
       NST.listen "*" (show port) (\(lsock, _) ->
                                        NST.accept lsock (\(csock, _) -> do
                                                               _ <- callback csock
                                                               threadDelay 1000000
                                                               return ()))

  -- Do the onion mapping after that
  P.mapOnionV3 sock port port False pkey
