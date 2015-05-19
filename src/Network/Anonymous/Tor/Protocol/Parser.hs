-- | Parser defintions
--
-- Defines parsers used by the Tor Control protocol
--
--   __Warning__: This function is used internally by 'Network.Anonymous.Tor'
--                and using these functions directly is unsupported. The
--                interface of these functions might change at any time without
--                prior notice.
--

module Network.Anonymous.Tor.Protocol.Parser ( quotedString
                                             , unquotedString
                                             , reply
                                             , key
                                             , keyValue
                                             , value
                                             , token
                                             , tokens ) where

import           Control.Applicative                         ((*>), (<$>), (<*), (<*>),
                                                              (<|>))

import qualified Data.Attoparsec.ByteString                  as Atto
import qualified Data.Attoparsec.ByteString.Char8            as Atto8
import qualified Data.ByteString                             as BS
import qualified Data.ByteString.Char8                       as BS8
import           Data.Word                                   (Word8)
import qualified Network.Anonymous.Tor.Protocol.Parser.Ast   as A

import Debug.Trace (trace)

-- | Ascii offset representation of a double quote.
doubleQuote :: Word8
doubleQuote = 34

-- | Ascii offset representation of a single quote.
singleQuote :: Word8
singleQuote = 39

-- | Ascii offset representation of a backslash.
backslash :: Word8
backslash = 92

-- | Ascii offset representation of a minus '-' symbol
minus :: Word8
minus = 45

-- | Ascii offset representation of a plus '+' symbol
plus :: Word8
plus = 43

-- | Ascii offset representation of a space ' ' character
space :: Word8
space = 32

-- | Ascii offset representation of an equality sign.
equals :: Word8
equals = 61

-- | Parses a single- or double-quoted string, and returns all bytes within the
--   value; the unescaping is beyond the scope of this function (since different
--   unescaping mechanisms might be desired).
quotedString :: Atto.Parser BS.ByteString
quotedString =
  let quoted :: Word8                     -- ^ The character used for quoting
             -> Atto.Parser BS.ByteString -- ^ The value inside the quotes, without the surrounding quotes
      quoted c = (Atto.word8 c *> escaped c <* Atto.word8 c)

      -- | Parses an escaped string, with an arbitrary surrounding quote type.
      escaped :: Word8 -> Atto.Parser BS.ByteString
      escaped c = BS8.concat <$> Atto8.many'
                       -- Make sure that we eat pairs of backslashes; this will make sure
                       -- that a string such as "\\\\" is interpreted correctly, and the
                       -- ending quoted will not be interpreted as escaped.
                  (    Atto8.string (BS8.pack "\\\\")

                       -- This eats all escaped quotes and leaves them in tact; the unescaping
                       -- is beyond the scope of this function.
                   <|> Atto8.string (BS.pack [backslash, c])

                       -- And for the rest: eat everything that is not a quote.
                   <|> (BS.singleton <$> Atto.satisfy (/= c)))

  in quoted doubleQuote <|> quoted singleQuote

-- | An unquoted string is "everything until a whitespace or newline is reached".
unquotedString :: Atto.Parser BS.ByteString
unquotedString =
  Atto8.takeWhile1 (not . Atto8.isSpace)

reply :: Atto.Parser A.Reply
reply = do
  -- A reply is a series of lines that look like 250-Foo or 250+Bar and then
  -- followed by a line that uses a space like 250 Wombat.
  --
  -- Let's parse all these lines into a reply.
  replies   <- Atto.many' (replyLine minus <|> replyLine plus)
  lastReply <- replyLine space

  return $ A.Reply (replies ++ [lastReply])

  where
    replyLine :: Word8 -> Atto.Parser A.Line
    replyLine c = A.Line <$> Atto8.decimal <*> (Atto.word8 c *> tokens) <* Atto8.endOfLine

-- | Parses either a quoted value or an unquoted value
value :: Atto.Parser BS.ByteString
value =
  quotedString <|> unquotedString

-- | Parses key and value
keyValue :: Atto.Parser A.Token
keyValue = do
  A.Token k _ <- key
  _ <- Atto.word8 equals
  v <- value

  return (A.Token k (Just v))

-- | Parses a key, which is anything until either a space has been reached, or
--   an '=' is reached.
key :: Atto.Parser A.Token
key =
  let isKeyEnd '=' = True
      isKeyEnd c   = Atto8.isSpace c

  in flip A.Token Nothing <$> Atto8.takeWhile1 (not . isKeyEnd)

-- | A Token is either a Key or a Key/Value combination.
token :: Atto.Parser A.Token
token =
  Atto.skipWhile Atto8.isHorizontalSpace *> (keyValue <|> key)

-- | Parser that reads keys or key/values
tokens :: Atto.Parser [A.Token]
tokens =
  Atto.many' token
