{-# LANGUAGE DeriveDataTypeable #-}

-- | Tor error types, inspired by System.IO.Error
module Network.Anonymous.Tor.Error where

import Data.Typeable     (Typeable)

import Control.Monad.IO.Class
import Control.Exception (throwIO)
import Control.Exception.Base (Exception)

-- | Error type used
type TorError = TorException

-- | Exception that we use to throw. It is the only type of exception
--   we throw, and the type of error is embedded within the exception.
data TorException = TorError {
  toreType :: TorErrorType -- ^ Our error type
  } deriving (Show, Eq, Typeable)

-- | Derives our Tor exception from the standard exception, which opens it
--   up to being used with all the regular try/catch/bracket/etc functions.
instance Exception TorException

-- | An abstract type that contains a value for each variant of 'TorError'
data TorErrorType
  = Timeout
  | Unreachable
  | ProtocolError
  | PermissionDenied
  deriving (Show, Eq)

-- | Generates new TorException
mkTorError :: TorErrorType -> TorError
mkTorError t = TorError { toreType = t }

-- | Tor error when a timeout has occurred
timeoutErrorType :: TorErrorType
timeoutErrorType = Timeout

-- | Tor error when a host was unreachable
unreachableErrorType :: TorErrorType
unreachableErrorType = Unreachable

-- | Tor error when communication with the SAM bridge fails
protocolErrorType :: TorErrorType
protocolErrorType = ProtocolError

-- | Tor error when communication with the SAM bridge fails
permissionDeniedErrorType :: TorErrorType
permissionDeniedErrorType = PermissionDenied

-- | Raise an Tor Exception in the IO monad
torException :: (MonadIO m)
             => TorException
             -> m a
torException = liftIO . throwIO

-- | Raise an Tor error in the IO monad
torError :: (MonadIO m)
         => TorError
         -> m a
torError = torException
