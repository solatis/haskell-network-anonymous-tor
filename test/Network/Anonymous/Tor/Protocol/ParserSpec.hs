{-# LANGUAGE OverloadedStrings #-}

module Network.Anonymous.Tor.Protocol.ParserSpec where

import qualified Data.ByteString                         as BS
import qualified Data.ByteString.Char8                   as BS8

import           Network.Anonymous.Tor.Protocol.Parser
import           Network.Anonymous.Tor.Protocol.Parser.Ast

import           Test.Hspec
import           Test.Hspec.Attoparsec

testDestination :: BS.ByteString
testDestination = "TedPIHKiYHLLavX~2XgghB-jYBFkwkeztWM5rwyJCO2yR2gT92FcuEahEcTrykTxafzv~4jSQOL5w0EqElqlM~PEFy5~L1pOyGB56-yVd4I-g2fsM9MGKlXNOeQinghKOcfbQx1LVY35-0X5lQSNX-8I~U7Lefukj7gSC5hieWkDS6WiUW6nYw~t061Ra0GXf2qzqFTB4nkQvnCFKaZGtNwOUUpmIbF0OtLyr6TxC7BQKgcg4jyZPS1LaBO6Wev0ZFYiQHLk4S-1LQFBfT13BxN34g-eCInwHlYeMD6NEdiy0BYHhnbBTq02HbgD3FjxW~GBBB-6a~eFABaIiJJ08XR8Mm6KKpNh~gQXut2OLxs55UhEkqk8YmTODrf6yzWzldCdaaAEVMfryO9oniWWCVl1FgLmzUHPGQ3yzvb8OlXiED2hunEfaEg0fg77FRDnYJnDHMF7i5zcUzRGb67rUa1To~H65hR9cFNWTAwX4svC-gRbbvxfi-bthyj-QqeBBQAEAAcAAOEyRS5bFHDrXnWpsjcRvpQj436gS4iCjCzdOohWgeBKC~gfLVY658op9GF6oRJ78ezPN9FBE0JqNrAM75-uL9CIeJd8JUwdldm83RNSVI1ZPZBK-5F3DgIjTsqHDMzQ9xPETiBO2UZZogXSThx9I9uYuAtg296ZhziKjYnl7wi2i3IgQlNbuPW16ajOcNeKnL1OqFipAL9e3k~LEhgBNM3J2hK1M4jO~BQ19TxIXXUfBsHFU4YjwkAOKqOxR1iP8YD~xUSfdtF9mBe6fT8-WW3-n2WgHXiTLW3PJjJuPYM4hNKNmsxsEz5vi~DE6H1pUsPVs2oXFYKZF3EcsKUVaAVWJBarBPuVNYdJgIbgl1~TJeNor8hGQw6rUTJFaZ~jjQ=="

spec :: Spec
spec = do
  describe "parsing quoted string" $ do
    it "it should succeed when providing a doublequoted string" $
      let msg :: BS.ByteString
          msg = "\"foo\""

      in msg ~> quotedString `shouldParse` "foo"

    it "it should succeed when providing a doublequoted value with spaces" $
      let msg :: BS.ByteString
          msg = "\"foo bar\""

      in msg ~> quotedString `shouldParse` "foo bar"

    it "it should succeed when providing a doublequoted value with an escaped quote" $
      let msg :: BS.ByteString
          msg = "\"foo \\\" bar\""

      in msg ~> quotedString `shouldParse` "foo \\\" bar"

    it "it should stop after a doublequoted value has been reached" $
      let msg :: BS.ByteString
          msg = "\"foo bar\" \"baz\""

      in msg ~> quotedString `shouldParse` "foo bar"

  describe "parsing unquoted strings" $ do
    it "it should succeed when providing a simple value" $
      let msg :: BS.ByteString
          msg = "foo"

      in msg ~> unquotedString `shouldParse` "foo"

    it "it should stop after whitespace" $
      let msg :: BS.ByteString
          msg = "foo bar"

      in msg ~> unquotedString `shouldParse` "foo"

    it "it should stop after a newline" $
      let msg :: BS.ByteString
          msg = "foo\r\nbar"

      in msg ~> unquotedString `shouldParse` "foo"

  describe "parsing replies" $ do
    it "should succeed on a single line reply" $
      let msg :: BS.ByteString
          msg = "250 OK\n"

      in msg ~> reply `shouldParse` (Reply [Line 250 [Token "OK" Nothing]])

    it "should succeed on a multi line reply" $
      let msg :: BS.ByteString
          msg = "250-Foo Bar\n250 OK\n"

      in msg ~> reply `shouldParse` (Reply [Line 250 [Token "Foo" Nothing, Token "Bar" Nothing],
                                            Line 250 [Token "OK" Nothing]])

    it "should parse protocolinfo reply" $
      let msg :: BS.ByteString
          msg = BS8.unlines [ "250-PROTOCOLINFO 1"
                            , "250-AUTH METHODS=COOKIE,SAFECOOKIE,HASHEDPASSWORD COOKIEFILE=\"C:\\\\Users\\\\leon\\\\Desktop\\\\Tor Browser\\\\Browser\\\\TorBrowser\\\\Data\\\\Tor\\\\control_auth_cookie\""
                            , "250-VERSION Tor=\"0.2.6.7\""
                            , "250 OK"]

      in msg ~> reply `shouldParse` (Reply [  Line 250 [Token "PROTOCOLINFO" Nothing, Token "1" Nothing]
                                            , Line 250 [Token "AUTH" Nothing, Token "METHODS" (Just "COOKIE,SAFECOOKIE,HASHEDPASSWORD"), Token "COOKIEFILE" (Just "C:\\\\Users\\\\leon\\\\Desktop\\\\Tor Browser\\\\Browser\\\\TorBrowser\\\\Data\\\\Tor\\\\control_auth_cookie")]
                                            , Line 250 [Token "VERSION" Nothing, Token "Tor" (Just "0.2.6.7")]
                                            , Line 250 [Token "OK" Nothing]])
