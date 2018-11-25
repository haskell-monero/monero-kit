import           Monero
import           Test.Hspec
import           Test.QuickCheck

main :: IO ()
main = hspec $ do

  describe "stealth addresses" $ do
    it "should match the output of the reference client" False
    it "should recognize a generated stealth address" False
    -- isAssociatedStealth (viewPriv sk) (toPublic sk) <$> generateStealth (toPublic sk) == m True

  describe "subaddresses" $ do
    it "should match the output of the reference wallet" False

