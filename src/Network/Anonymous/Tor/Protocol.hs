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
module Network.Anonymous.Tor.Protocol ( NST.connect ) where

import qualified Network.Simple.TCP                        as NST
import qualified Network.Attoparsec                        as NA

import qualified Network.Anonymous.I2P.Error               as E
