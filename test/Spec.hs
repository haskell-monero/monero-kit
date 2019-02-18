{-# LANGUAGE OverloadedStrings #-}

import           Crypto.ECC.Edwards25519
import           Crypto.ECC.Edwards25519.Extra
import qualified Data.ByteString.Base16        as B16
import qualified Data.ByteString.Short         as BSS
import           Data.Serialize
import qualified Data.Vector                   as Vector
import           Monero
import           Monero.Bulletproofs
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


    describe "subaddresses" $

        it "should match the output of the reference wallet" False


    describe "encodings" $ do

        it "should correctly encode varint" $ do
            encode (VarInt 0x11) `shouldBe` "\x11"
            encode (VarInt 0xff) `shouldBe` "\xff\x01"
            encode (VarInt 0x010203) `shouldBe` "\x83\x84\x04"
            encode (VarInt 0xff00000000) `shouldBe` "\x80\x80\x80\x80\xF0\x1F"
            -- ^ from the monero test suite

        it "should correctly decode varint" $ do
            decode "\x22" `shouldBe` (Right $ VarInt 0x22)
            decode "\xff\x01" `shouldBe` (Right $ VarInt 0xff)
            decode "\x83\x84\x04" `shouldBe` (Right $ VarInt 0x010203)
            decode "\x80\x80\x80\x80\xF0\x1F" `shouldBe` (Right $ VarInt 0xff00000000)
            -- ^ from the monero test suite


    describe "blocks" $

        describe "block hash" $ do

            let toHash256 = Hash256 . BSS.toShort . fst . B16.decode

                -- Block 1727411

                coinbaseTxId1727411 = TransactionId $
                    toHash256 "0b51148b682202951a1d9e0c84ec926f7e97cb8c40f1c905a835c9cc8889d9b9"

                txIds1727411 = Vector.fromList $ fmap (TransactionId . toHash256)
                    [ "00cd3a1a5f3dc747d8fa3c7ae564995eaf9de8413872bf1a5193d6c3874f993c"
                    , "9c83ec05ae04244681a50a29ee05e1d76351508e9349fe0f1d5b3094580ba5f3"
                    , "bbb969bfb61df5e00941cc760c467c29d61d9cdbeed1cdb3f3e9db05eaabc151"
                    ]

                blockId1727410 = toHash256 "017bc5c45f25bc189a62f315fd3c8b0ec1f43abbbd894d8dba6c5daac7e78109"
                blockId1727411 = toHash256 "a5e80cbdfc424ccfafbfe3540b9412606694d3457e80a4454b720effff4f8901"

                header1727411 = BlockHeader 9 9 1544917122 blockId1727410 477219081


                -- Block 1728234

                blockId1728233 = toHash256 "a343502b990f7a9be7c9d10829eda293e13a05d765edca9ec64da68e6c6365e8"
                blockId1728234 = toHash256 "9dd1e36359d6f501b883fa92da1153b750e36316f7a4243f0a233c588fe8013d"

                coinbaseTxId1728234 = TransactionId
                    $ toHash256 "2587c80213b162034cabbca3a7eb9cf6205506b60b0f47f449e067e070e7aa34"

                header1728234 = BlockHeader 9 9 1545016412 blockId1728233 4253024397

            it "should compute block id 1727411" $
                blockId1727411 == blockId header1727411 coinbaseTxId1727411 txIds1727411

            it "should compute block id 1728234" $
                blockId1728234 == blockId header1728234 coinbaseTxId1728234 Vector.empty


    describe "utils" $ do

        let f x y = "(" ++ x ++ "," ++ y ++ ")"

        it "should treeReduce correctly" $
            treeReduce f (Vector.fromList $ show <$> [1..7]) == "((1,(2,3)),((4,5),(6,7)))"

    describe "crypto extras" $ do

        s <- runIO scalarGenerate

        it "should negate a scalar" $
            scalarNeg s `scalarAdd` s == zeroScalar

        it "should invert a scalar" $
            maybe False (\sInv -> sInv `scalarMul` s == scalarOne) $ scalarInv s

    describe "rangeproofs" $ do

        r <- runIO $ proofRandomness 30
        p <- runIO $ generateParams 30

        it "should verify a rangeproof" $
            verify p (verifierRandomness r) $ prove p r 123454321
