-- Establish a baseline for performance of cryptographic functions

import           Control.Monad
import           Criterion.Main
import           Crypto.ECC.Edwards25519
import           Data.Bits
import           Data.Word

-- | Exponentiation by squaring
expFaster :: Bits a => a -> Point -> Point
expFaster x p
  | x == bit 0
  = p
  | x `testBit` 0
  = p `pointAdd` expFaster (x `shiftR` 1) (pointDouble p)
  | otherwise
  = expFaster (x `shiftR` 1) (pointDouble p)


main = do
  [x0, x1] <- replicateM 2 scalarGenerate
  let point = toPoint x0
  defaultMain
    [ bgroup "scalar-point multiplication" [
        bench "multiply basepoint" $ nf toPoint x0
      , bench "multiply other point" $ nf (pointMul x1) point
      , bench "faster multiply" $ nf (expFaster (18425743073708551615  :: Word64)) point
      ]
    ]
