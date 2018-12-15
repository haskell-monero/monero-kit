{-# LANGUAGE OverloadedStrings #-}

import           Data.Serialize
import           Monero
import           Test.Hspec
import           Test.QuickCheck

main :: IO ()
main = hspec $ do

    describe "stealth addresses" $ do

        it "should match the output of the reference client" False

        sk <- runIO generateRandomKeypair
        stealth <- runIO $ generateStealth (toPublic sk)

        it "should recognize a generated stealth address" $
            stealth `shouldSatisfy` isAssociatedStealth (viewKey sk) (toPublic sk)


    describe "subaddresses" $ do

        it "should match the output of the reference wallet" False


    describe "encodings" $ do

        it "should correctly encode varint" $ do
            encode (VarInt 0x11) `shouldBe` "\x11"
            encode (VarInt 0xff) `shouldBe` "\xff\x01"
            encode (VarInt 0x010203) `shouldBe` "\x83\x84\x04"

        it "should correctly decode varint" $ do
            decode "\x22" `shouldBe` (Right $ VarInt 0x22)
            decode "\xff\x01" `shouldBe` (Right $ VarInt 0xff)
            decode "\x83\x84\x04" `shouldBe` (Right $ VarInt 0x010203)
