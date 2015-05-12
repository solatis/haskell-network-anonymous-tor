module Network.Anonymous.Tor.Util where

import qualified Network.Anonymous.Tor.Error as E

-- | Returns true if exception is of a certain type
isTorError :: E.TorErrorType -> E.TorException -> Bool
isTorError lhs (E.TorError rhs) = lhs == rhs
