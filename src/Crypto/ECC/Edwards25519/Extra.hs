-- |
-- Module: Crypto.ECC.Edwards25519.Extra
--
-- Support for converting integers to scalars; and subtraction for scalars.


module Crypto.ECC.Edwards25519.Extra
    ( toScalar
    , scalarSub
    , scalarNeg
    , pointMulInt

    -- * Constants
    , groupOrder
    , zeroPoint
    , zeroScalar
    , negativeOne
    ) where

import           Crypto.ECC.Edwards25519
import           Crypto.Error
import           Data.Bits
import           Data.ByteString         as BS
import           Data.ByteString.Builder as BSB
import           Data.ByteString.Lazy    as BSL
import           Data.Int
import           Data.Word

-- Order of the Curve25519 group
groupOrder :: Integer
groupOrder = 2^252 + 27742317777372353535851937790883648493


-- Useful constants

zeroPoint = toPoint zeroScalar
zeroScalar = throwCryptoError . scalarDecodeLong $ BS.empty
negativeOne = throwCryptoError . scalarDecodeLong . BS.pack . littleEndian $ groupOrder - 1


-- Some "missing" combinators

scalarNeg = scalarMul negativeOne
scalarSub x = scalarAdd x . scalarNeg


-- | Multiply a point by an 'Int64' instead of a 'Scalar'
pointMulInt :: Int64 -> Point -> Point
pointMulInt = pointMul . toScalar


-- | Warning this only works for non-negative values
toScalar x
    | x >= 0
    = toScalarPos x

    | x < 0
    = scalarNeg . toScalarPos . negate $ x
  where
    toScalarPos = throwCryptoError . scalarDecodeLong
        . BSL.toStrict . BSB.toLazyByteString . BSB.int64LE


-- | We need a version of little endian encoding for huge ints
littleEndian :: Integer -> [Word8]
littleEndian x
    | x == 0
    = []

    | otherwise
    = fromIntegral (x .&. 255) : littleEndian (x `shiftR` 8)


