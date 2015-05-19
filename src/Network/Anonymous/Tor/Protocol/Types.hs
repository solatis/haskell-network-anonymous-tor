-- | Types used by the 'Network.Anonymous.Tor.Protocol' module

module Network.Anonymous.Tor.Protocol.Types where

import qualified Data.Text as T

-- | Authentication types supported by the Tor service
data AuthMethod =
  Cookie | SafeCookie | HashedPassword

  deriving (Eq)

instance Read AuthMethod where
  readsPrec _ "COOKIE" = [(Cookie, "")]
  readsPrec _ "SAFECOOKIE" = [(SafeCookie, "")]
  readsPrec _ "HASHEDPASSWORD" = [(HashedPassword, "")]
  readsPrec _ s = error ("Not a valid AuthMethod: " ++ s)

instance Show AuthMethod where
  show Cookie = "COOKIE"
  show SafeCookie = "SAFECOOKIE"
  show HashedPassword = "HASHEDPASSWORD"

-- | Information about our protocol (and version)
data ProtocolInfo = ProtocolInfo {
  protocolVersion :: Integer,

  torVersion      :: [Integer],

  authMethods     :: [AuthMethod],

  cookieFile      :: Maybe T.Text

  } deriving (Show, Eq)
