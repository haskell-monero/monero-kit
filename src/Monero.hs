-- |
-- Module    : Monero
-- Stability : experimental

{-# LANGUAGE DeriveAnyClass    #-}
{-# LANGUAGE DeriveGeneric     #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}
{-# LANGUAGE TypeFamilies      #-}

{-# OPTIONS_GHC -fdefer-typed-holes #-}

module Monero (
    -- * Keys and addresses
      PublicKeypair (..)
    , ViewKey (..)
    , PrivateKeypair
    , privateKeypair
    , toPublic
    , viewKey
    , generateRandomKeypair

    , StealthAddress (..)
    , isAssociatedStealth
    , generateStealth

    , subAddress

    -- * Blocks and transactions

    , Id (..)
    , Hash256 (..)

    , Transaction

    , BlockHeader (..)
    , Block (..)
    , blockId

    -- * Others
    , VarInt (..)
    , varInt
    , treeReduce

    ) where

import           Control.DeepSeq         (NFData)
import           Control.Monad
import           Crypto.ECC.Edwards25519
import           Crypto.Error
import           Crypto.Hash
import           Crypto.Random
import           Data.Bits
import           Data.ByteArray
import           Data.ByteString         (ByteString)
import qualified Data.ByteString         as BS
import qualified Data.ByteString.Builder as BS
import qualified Data.ByteString.Lazy    as BSL
import           Data.ByteString.Short   (ShortByteString)
import qualified Data.ByteString.Short   as BSS
import           Data.Int
import           Data.Maybe
import           Data.Serialize
import           Data.Vector             (Vector)
import qualified Data.Vector             as Vector
import           Data.Word
import           GHC.Generics            (Generic)


-- ~~~~~~~~~~~~~ --
-- General types --
-- ~~~~~~~~~~~~~ --

-- | Identifiers of all kinds
data family Id a


newtype instance Id Transaction = TransactionId { unTransactionId :: Hash256 }
    deriving Eq


instance Serialize (Id Transaction) where

    get = (TransactionId . Hash256) <$> getShortByteString 32
    put (TransactionId (Hash256 x)) = putShortByteString x


-- | For when bytes are actually a hash digest
newtype Hash256 = Hash256 { unHash256 :: ShortByteString }
    deriving (Eq, Show)


instance Serialize Hash256 where

    get = Hash256 <$> getShortByteString 32
    put (Hash256 x) = putShortByteString x


-- ~~~~~~~~~ --
-- Addresses --
-- ~~~~~~~~~ --


-- | Every Monero output is owned by a keypair consisting of two Ed25519 keys.
-- These keys are used differently from one another and have different
-- consequences if compromised (separately).
data PublicKeypair
    = PublicKeypair
    { spendPubkey :: Point
    , viewPubkey  :: Point
    } deriving (Show, Eq)


-- | This is the pair of private keys associated with a 'PublicKeypair'
data PrivateKeypair
    = PrivateKeypair
    { spendPriv :: Scalar
    , viewPriv  :: Scalar
    } deriving (Show, Eq, Generic, NFData)


-- | Generate a 'PrivateKeypair' from the spend part of the 'PrivateKeypair' by taking a
-- hash of the private key for the view key.
privateKeypair :: Scalar -> PrivateKeypair
privateKeypair pk = PrivateKeypair pk (keccak256Scalar pk)


keccak256Scalar :: Scalar -> Scalar
keccak256Scalar = throwCryptoError . scalarDecodeLong . scrubbedKeccak . scalarEncode


scrubbedKeccak :: ByteString -> ScrubbedBytes
scrubbedKeccak = convert . keccak256


keccak256 :: ByteString -> Digest Keccak_256
keccak256 = hash


-- | The view (private) key of an address can be shared with a third party to
-- give them visibility over the transactions bound for the address, without
-- giving them the ability to spend
newtype ViewKey = ViewKey { unViewKey :: Scalar }
    deriving Eq


-- | Extract the private view key from a keypair
viewKey :: PrivateKeypair -> ViewKey
viewKey = ViewKey . viewPriv


-- | Generate a random keypair
generateRandomKeypair :: MonadRandom m => m PrivateKeypair
generateRandomKeypair = privateKeypair <$> scalarGenerate


-- | All Monero payments spend to ephemeral addresses, which only the owner of
-- the view private key can recognize.
data StealthAddress
    = StealthAddress
    { stealthNonce  :: Point
    , stealthPubkey :: Point
    } deriving (Eq, Show, Generic, NFData)


-- | Test to see if a stealth address (R = rG, r A + B = a R + B) belongs to
-- the given PublicKeypair
isAssociatedStealth :: ViewKey -> PublicKeypair -> StealthAddress -> Bool
isAssociatedStealth (ViewKey viewKey) PublicKeypair{..} StealthAddress{..} =
    (viewKey `pointMul` stealthNonce `pointAdd` spendPubkey) == stealthPubkey


-- | Get the public key associated to a private key
toPublic :: PrivateKeypair -> PublicKeypair
toPublic PrivateKeypair{..} = PublicKeypair (toPoint spendPriv) (toPoint viewPriv)


-- | Create a new stealth address
generateStealth :: MonadRandom m => PublicKeypair -> m StealthAddress
generateStealth PublicKeypair{..} =
    scalarGenerate >>= \r ->
        let stP = r `pointMul` viewPubkey `pointAdd` spendPubkey in
        pure $ StealthAddress (toPoint r) stP


-- | Derive a subaddress
--
-- Subaddresses are parameterized by major and minor indices @(i,j)@.  The major
-- index represents a user-level account, whereas the minor index tracks the
-- position in a chain of subaddresses under an account.
--
-- Given a pair of private keys @(a,b)@ and a pair of indices @(i,j)@ the
-- corresponding subaddress pair of private keys is @(a * (b + m), b + m)@ where
--
-- > m = le_int32_to_scalar(keccak256("SubAddr"|a|i|j))
--
-- monero-project/monero:
--
-- - @ab6c17cc154914df61778ad48577ed70d8b03f88:src\/device/device_default.cpp#L127@
-- - @ab6c17cc154914df61778ad48577ed70d8b03f88:src\/device/device_default.cpp#L197@
--
subAddress :: PrivateKeypair -> Word32 -> Word32 -> PrivateKeypair
subAddress PrivateKeypair{..} majorIndex minorIndex = PrivateKeypair s v
    where
        s = k `scalarAdd` spendPriv
        v = viewPriv `scalarMul` s
        k = throwCryptoError $ scalarDecodeLong m
        m = keccak256 . BSL.toStrict . BS.toLazyByteString $
            BS.byteString "SubAddr" <>
            BS.byteString (scalarEncode viewPriv) <>
            BS.word32LE majorIndex <>
            BS.word32LE minorIndex


-- ~~~~~~~~~~~~ --
-- Transactions --
-- ~~~~~~~~~~~~ --


data Transaction
    = Transaction
    { version       :: Word64
    , unlockTime    :: Word64
    , vin           :: [TxIn]
    , vout          :: [TxOut]
    , extra         :: ByteString
    , signatures    :: [[Signature]]
    , rctSignatures :: RctSig
    } deriving Eq

instance Serialize Transaction where

    get = _
    put = _


data Signature = Signature
    deriving Eq


data RctSig = RctSig
    deriving Eq


data TxIn
    = TxIn
    {
    } deriving Eq


data TxOut
    = TxOut
    {
    } deriving Eq


transactionId = _


-- ~~~~~~ --
-- Blocks --
-- ~~~~~~ --

-- | A Monero block header
data BlockHeader
    = BlockHeader
    { majorVersion   :: Word8
    , minorVersion   :: Word8
    , blockTimestamp :: Word64
    , previousBlock  :: Hash256
    -- ^ FIXME confirm type
    , blockNonce     :: Word32
    } deriving Eq


instance Serialize BlockHeader where

    get = BlockHeader <$>
        getVarInt <*>
        getVarInt <*>
        getVarInt <*>
        get <*>
        get
        where
            getVarInt :: Integral a => Get a
            getVarInt = fromVarInt <$> get


    put BlockHeader{..} = do
        put (varInt majorVersion)
        put (varInt minorVersion)
        put (varInt blockTimestamp)
        put previousBlock
        put blockNonce


-- | A Monero block
data Block
    = Block
    { blockHeader       :: BlockHeader
    , coinbaseTx        :: Transaction
    , transactionHashes :: Vector (Id Transaction)
    } deriving Eq


instance Serialize Block where

    get = Block <$> get <*> get <*> getVector
    put Block{..} = put blockHeader >> put coinbaseTx <* putVector transactionHashes


-- | Compute the hash of a block as @keccak256@ over the concatenation of
--
-- * serialized block header
-- * Merkle root of collection of transaction ids @[coinbase, tx0, tx1, ..]@
-- * Included transaction count (varint encoded)
--
-- TODO include the logic for dealing with block 202612
blockId :: BlockHeader
    -> Id Transaction
    -- ^ coinbase transaction
    -> Vector (Id Transaction)
    -- ^ included transactions
    -> Hash256
blockId header coinbaseId txHashes =
    Hash256 $ BSS.toShort $ convert $ keccak256 $ payload
    where

        txCount = Vector.length txHashes + 1 -- add one for the coinbase
        hashes = unTransactionId <$> (coinbaseId `Vector.cons` txHashes)
        txRoot = treeReduce hashMerge hashes

        payload = runPut $ put header >> put txRoot >> put (varInt txCount)


hashMerge :: Hash256 -> Hash256 -> Hash256
hashMerge (Hash256 x) (Hash256 y) = Hash256 $ BSS.toShort $ convert $ keccak256 (BSS.fromShort $ x <> y)


-- | A generic implementation of the algorithm used by Monero to compute the
-- Merkle root of a list of transactions
--
-- _Assumption: input vectors are nonempty_
treeReduce :: (a -> a -> a) -> Vector a -> a
treeReduce op xs
    | n == 1 = xs Vector.! 0
    | n == m = treeReduce' xs
    | otherwise = treeReduce' xs'
    where

        n = Vector.length xs

        -- largest power of two not exceeding n
        m = let l = floor (logBase 2 (fromIntegral n)) in 1 `shiftL` l

        treeReduce' xs
            | Vector.length xs == 1 = xs Vector.! 0
            | otherwise = treeReduce' $ halve xs

        halve xs = Vector.generate (Vector.length xs `shiftR` 1) $ \i ->
            let j = 2*i
                u = xs Vector.! j
                v = xs Vector.! (j+1)
            in u `op` v


        -- Shrink xs to have length m by applying op to the trailing 2 * (m - k) elements
        xs' = let k = 2*m - n in
                Vector.generate m $ \i ->
                    if i < k
                    then xs Vector.! i
                    else
                        let j = 2 * i - k
                            u = xs Vector.! j
                            v = xs Vector.! (j+1)
                        in u `op` v



-- ~~~~~~~~~~~~~ --
-- Wire protocol --
-- ~~~~~~~~~~~~~ --

-- | In Monero, varint is an encoding for arbitrary bitstreams
newtype VarInt
    = VarInt { unVarInt :: Integer }
    deriving (Eq, Ord, Show)


varInt :: Integral a => a -> VarInt
varInt = VarInt . fromIntegral


fromVarInt :: Num a => VarInt -> a
fromVarInt (VarInt x) = fromIntegral x


getVector :: Serialize a => Get (Vector a)
getVector =
    get >>= \(VarInt l) ->
    sequence $ Vector.generate (fromIntegral l) (const get)


putVector :: Serialize a => Putter (Vector a)
putVector v = put (varInt $ Vector.length v) <* (traverse put v)


-- | Varint serialization in Monero is different from Bitcoin's.  In this
-- encoding, a non-negative integer @n@ serializes into @ceiling (log_2 n / 7)@
-- bytes.
instance Serialize VarInt where

    get = VarInt <$> go 0
        where
            go n = getWord8 >>= \w ->
                let b = (fromIntegral $ w .&. 0x7f) `shiftL` (7 * n) in
                if testBit w 7
                    then (+ b) <$> go (n+1)
                    else return b

    put (VarInt i) = go i
        where
            w8 :: Integer -> Word8
            w8 = fromIntegral
            go i
                | i >= 0x80
                = let x = (w8 i .&. 0x7f) .|. 0x80 in
                    put x >> go (i `shiftR` 7)
                | otherwise = put $ w8 i


