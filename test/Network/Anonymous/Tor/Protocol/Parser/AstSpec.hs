{-# LANGUAGE OverloadedStrings #-}

module Network.Anonymous.Tor.Protocol.Parser.AstSpec where

import qualified Data.Attoparsec.ByteString                as Atto
import           Network.Anonymous.Tor.Protocol.Parser.Ast

import           Test.Hspec

spec :: Spec
spec = do
  describe "looking up keys" $ do
    it "should return true when a key exists" $
      let tokens = [Token "foo" Nothing]
      in  key "foo" tokens `shouldBe` True

    it "should return false when a key does not exist" $
      let tokens = [Token "foo" Nothing]
      in  key "bar" tokens `shouldBe` False

    it "should return true when a key has a value associated with it" $
      let tokens = [Token "foo" (Just "bar")]
      in  key "foo" tokens `shouldBe` True

    it "should return true when a key exists multiple times" $
      let tokens = [Token "foo" Nothing, Token "foo" Nothing]
      in  key "foo" tokens `shouldBe` True

  describe "looking up values" $ do
    it "should return value when a key has a value" $
      let tokens = [Token "foo" (Just "bar")]
      in  value "foo" tokens `shouldBe` Just ("bar")

    it "should return Nothing when a key has no value" $
      let tokens = [Token "foo" Nothing]
      in  value "foo" tokens `shouldBe` Nothing

    it "should return Nothing when a key does not exist" $
      let tokens = [Token "foo" Nothing]
      in  value "bar" tokens `shouldBe` Nothing

    it "should return first occurence if a key exists more than one time" $
      let tokens = [Token "foo" (Just "bar"), Token "foo" (Just "wombat")]
      in  value "foo" tokens `shouldBe` (Just "bar")

  describe "looking up values and parsing them" $ do
    let wombatParser = Atto.string "wombat"

    it "should succeed when parsing digits" $
      let tokens = [Token "foo" (Just "wombat")]

      in  valueAs wombatParser "foo" tokens `shouldBe` Just ("wombat")

    it "should return nothing when value is not found" $
      let tokens = [Token "foo" (Just "wombat")]

      in  valueAs wombatParser "bar" tokens `shouldBe` Nothing

    it "should return nothing when value cannot be parsed" $
      let tokens = [Token "foo" (Just "abcd")]

      in  valueAs wombatParser "foo" tokens `shouldBe` Nothing

  describe "looking up lines from replies" $ do
    it "should look up a simple line" $
      let reply = [Line 250 [Token "foo" Nothing]]
      in  line "foo" reply `shouldBe` Just (Line 250 [Token "foo" Nothing])

    it "should fail when no line exists" $
      let reply = [Line 250 [Token "foo" Nothing]]
      in  line "bar" reply `shouldBe` Nothing

    it "should fail on case sensitivity" $
      let reply = [Line 250 [Token "Foo" Nothing]]
      in  line "foo" reply `shouldBe` Nothing

  describe "looking up status codes from replies" $ do
    it "should return the correct status code" $
      let reply = [Line 250 [Token "foo" Nothing]]
      in  statusCode reply `shouldBe` 250

    it "should return the status code of the first line" $
      let reply = [Line 205 [Token "foo" Nothing], Line 250 [Token "foo" Nothing]]
      in  statusCode reply `shouldBe` 205
