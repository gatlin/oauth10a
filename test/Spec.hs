{-# LANGUAGE OverloadedStrings #-}

import Data.ByteString (ByteString)
import Data.ByteString (ByteString, append, empty)
import Data.ByteString.Char8 (pack, unpack)
import Control.Monad (mapM_)

import Net.OAuth.OAuth10a

{- Test data -}

ts :: ByteString
ts = "1318622958"

nonce :: ByteString
nonce = "kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg"

method :: ByteString
method = "POST"

url :: ByteString
url = "https://api.twitter.com/1/statuses/update.json"

creds :: Credentials
creds = Credentials {
    consumerKey = "xvz1evFS4wEEPTGEFPHBog",
    consumerSecret = "kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw",
    token = Just "370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb",
    tokenSecret = Just "LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE"
    }

{- Tests

For the most part the tests consist of `actual_*` functions with the correct
values and `gen_*` functions which attempt to create them.

-}

gen_param_string :: ByteString
gen_param_string =
    let params = [ Param "oauth_consumer_key" (consumerKey creds)
                 , Param "oauth_nonce" nonce
                 , Param "oauth_signature_method" "HMAC-SHA1"
                 , Param "oauth_timestamp" ts
                 , Param "oauth_version" "1.0"
                 , Param "oauth_token" (maybe "" id (token creds))
                 , Param "status"
                     "Hello Ladies + Gentlemen, a signed OAuth request!"
                 , Param "include_entities" "true"
                 ]
    in  param_string params

actual_param_string :: ByteString
actual_param_string = "include_entities=true&oauth_consumer_key=xvz1evFS4wEEPTGEFPHBog&oauth_nonce=kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1318622958&oauth_token=370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb&oauth_version=1.0&status=Hello%20Ladies%20%2B%20Gentlemen%2C%20a%20signed%20OAuth%20request%21"

actual_base_string :: ByteString
actual_base_string = "POST&https%3A%2F%2Fapi.twitter.com%2F1%2Fstatuses%2Fupdate.json&include_entities%3Dtrue%26oauth_consumer_key%3Dxvz1evFS4wEEPTGEFPHBog%26oauth_nonce%3DkYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1318622958%26oauth_token%3D370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb%26oauth_version%3D1.0%26status%3DHello%2520Ladies%2520%252B%2520Gentlemen%252C%2520a%2520signed%2520OAuth%2520request%2521"

gen_base_string :: ByteString
gen_base_string =
    let params = [ Param "oauth_consumer_key" (consumerKey creds)
                 , Param "oauth_nonce" nonce
                 , Param "oauth_signature_method" "HMAC-SHA1"
                 , Param "oauth_timestamp" ts
                 , Param "oauth_version" "1.0"
                 , Param "oauth_token" (maybe "" id (token creds))
                 , Param "status"
                     "Hello Ladies + Gentlemen, a signed OAuth request!"
                 , Param "include_entities" "true"
                 ]
    in  sig_base_string (param_string params) method url

actual_signing_key :: ByteString
actual_signing_key = "kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw&LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE"

gen_signing_key :: ByteString
gen_signing_key = signing_key (consumerSecret creds) (tokenSecret creds)

actual_signature :: ByteString
actual_signature = "tnnArxj06cWHq44gCs1OSKk/jLY="

gen_signature :: ByteString
gen_signature =
    let params = [ Param "oauth_consumer_key" (consumerKey creds)
                 , Param "oauth_nonce" nonce
                 , Param "oauth_timestamp" ts
                 , Param "oauth_signature_method" "HMAC-SHA1"
                 , Param "oauth_version" "1.0"
                 , Param "include_entities" "true"
                 , Param "oauth_token" (maybe "" id (token creds))
                 , Param "status"
                     "Hello Ladies + Gentlemen, a signed OAuth request!"
                 ]
        sk = signing_key (consumerSecret creds) (tokenSecret creds)
        base_string = sig_base_string (param_string params) method url
    in  sign sk base_string

test_percent_encoding :: Bool
test_percent_encoding =
    "%2Fuser%2F123456%2Fcourses" ==
    percent_encode( "/user/123456/courses" :: ByteString)

main :: IO ()
main = do
    mapM_ putStrLn [
        "",
        "Tests",
        "[test_percent_encoding] " ++ (show test_percent_encoding),
        "[test_param_string] " ++
            (show $ actual_param_string == gen_param_string),
        "[test_base_string] " ++ (show $
                                  actual_base_string == gen_base_string),
        "[test_signing_key] " ++
            (show $ actual_signing_key == gen_signing_key),
        "[test_signature] " ++
            (show $ actual_signature == gen_signature)
        ]
