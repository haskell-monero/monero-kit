-- Establish a baseline for performance of cryptographic functions

import           Control.Monad
import           Criterion.Main
import           Crypto.ECC.Edwards25519
import           Data.Bits
import           Data.Int
import           Data.Word
import           Monero

-- | Exponentiation by squaring
expFaster :: Bits a => a -> Point -> Point
expFaster x p
    | x == bit 0
    = p
    | x `testBit` 0
    = p `pointAdd` expFaster (x `shiftR` 1) (pointDouble p)
    | otherwise
    = expFaster (x `shiftR` 1) (pointDouble p)


main :: IO ()
main = do

    [x0, x1] <- replicateM 2 scalarGenerate
    let point = toPoint x0
    sk <- generateRandomKeypair
    let pk = toPublic sk

    defaultMain
        [ bgroup "scalar-point multiplication"
            [ bench "multiply basepoint" $ nf toPoint x0
            , bench "multiply other point" $ nf (pointMul x1) point
            , bench "faster multiply" $ nf (expFaster (18425743073708551615  :: Word64)) point
            ]
        , bgroup "addresses"
            [ bench "generate stealth address" $ nfIO (generateStealth pk)
            , bench "generate subaddress" $ nf (subAddress sk 1) 1
            ]
        ]
