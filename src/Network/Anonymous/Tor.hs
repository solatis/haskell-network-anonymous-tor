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

  -- * Server side
  -- $tor-server

  -- ** Setting up the context
  ) where

import           Control.Concurrent                      (forkIO)
import           Control.Concurrent.MVar
import           Control.Monad                           (forever)
import           Control.Monad.Catch

import qualified Data.ByteString                         as BS
import qualified Network.Socket                          as Network


--------------------------------------------------------------------------------
-- $tor-introduction
--
-- This module is an implementation of the SAMv3 protocol for Tor. Tor is an
-- internet anonimization network, similar to Tor. Whereas Tor is primarily
-- intended for privately browsing the world wide web, Tor is more application
-- oriented, and is intended for private communication between applications.
--
-- The general idea of the SAM interface to Tor is that you establish a master
-- connection with the SAM bridge, and create new, short-lived connections with
-- the SAM bridge for the communication with the individual peers.
--
-- Tor provides three different ways of communicating with other hosts:
--
--  * __Virtual Streams__: similar to reliable TCP sockets, data is guaranteed to
--    be delivered, and in order. You can accept virtual streams and connect to
--    remote virtual streams, and use regular sockets to transmit the actual
--    messages.
--
--  * __Repliable Datagrams__: unreliable delivery of messages to a remote host,
--    but adds a reply-to address to the message so the remote host can send a
--    message back.
--
--  * __Anonymous Datagrams__: unreliable delivery of messages to a remote host,
--    and the remote host has no way to find out who sent the message.
--
-- Different methods of communication have different performance characteristics,
-- and an application developer should take these into careful consideration when
-- developing an application.
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
