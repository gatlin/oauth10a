{-# LANGUAGE OverloadedStrings #-}

{- |
Module      : Net.OAuth.OAuth10a
Description : OAuth 1.0a implementation
Copyright   : 2016
License     : GPLv3

Maintainer  : Gatlin Johnson <gatlin@niltag.net>
Stability   : experimental
Portability : non-portable

Defines functions necessary for generating OAuth 1.0a Authorization headers.
-}

module Net.OAuth.OAuth10a
    ( auth_header
    , param_string
    , Param(..)
    , Credentials(..)
    , PercentEncode(..)
    , filterNonAlphanumeric
    , gen_nonce
    , timestamp
    , sig_base_string
    , signing_key
    , sign
    , create_header_string
    , oauth_sig
    ) where

import Network.HTTP.Client
import Network.HTTP.Types.Status (statusCode)
import Data.ByteString (ByteString)
import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString      as BS
import qualified Data.ByteString.Base64 as B64
import Data.ByteString.Char8 (pack, unpack)
import Data.ByteString.Builder (Builder)
import qualified Data.ByteString.Builder as BB
import Control.Monad.IO.Class
import Control.Monad (forM, mapM)
import System.Entropy (getEntropy)
import Data.Time.Clock.POSIX (getPOSIXTime)
import Data.List (sort, intersperse)
import Data.Monoid ((<>))
import Crypto.MAC.HMAC (hmac)
import Crypto.Hash.SHA1 (hash)

-- | HTTP request parameters
data Param = Param
    { paramKey   :: ByteString
    , paramValue :: ByteString
    } deriving (Show, Eq, Ord)

-- | Request credentials
data Credentials = Credentials
    { consumerKey :: ByteString
    , consumerSecret :: ByteString
    , token :: Maybe ByteString
    , tokenSecret :: Maybe ByteString
    } deriving (Show)

-- * Helpers
bs = BB.byteString
build = BL.toStrict . BB.toLazyByteString

-- | Filter all non-alphanumeric (by English standards) from a 'ByteString'
filterNonAlphanumeric :: ByteString -> ByteString
filterNonAlphanumeric = BS.pack . trunc . filter f . BS.unpack where
    f ch | ch >= 97 && ch <= 122 = True
         | ch >= 48 && ch <= 57 = True
         | otherwise = False
    trunc it | length it > 32 = take 32 it
             | otherwise = it

-- | Generate the request nonce
gen_nonce :: MonadIO m => m ByteString
gen_nonce = do
    random_bytes <- liftIO $ getEntropy 32
    return $ filterNonAlphanumeric $ B64.encode random_bytes

-- | Rounded integer number of seconds since the UNIX epoch
timestamp :: MonadIO m => m Integer
timestamp = liftIO $ round <$> getPOSIXTime

-- | Types which may be percent encoded
class PercentEncode t where
    percent_encode :: t -> t

instance PercentEncode ByteString where
    percent_encode = build . mconcat . map encodeChar . BS.unpack where
        encodeChar ch | unreserved' ch = BB.word8 ch
                      | otherwise = h2 ch
        unreserved' ch | ch >= 65 && ch <= 90 = True -- A-Z
                       | ch >= 97 && ch <= 122 = True -- a-z
                       | ch >= 48 && ch <= 57 = True -- 0-9
                       | ch == 95 = True -- _
                       | ch == 46 = True -- .
                       | ch == 126 = True -- ~
                       | ch == 45 = True -- -
                       | otherwise = False
        h2 v = let (a, b) = v `divMod` 16 in bs $ BS.pack [37, h a, h b]
        h i | i < 10 = 48 + i -- zero (0)
            | otherwise = 65 + i - 10 -- 65: A

instance PercentEncode Param where
    percent_encode (Param a b) = Param (percent_encode a) (percent_encode b)

-- | Generate a parameter string from a list of 'Param'
param_string :: [Param] -> ByteString
param_string = build .
    foldl (<>) mempty . intersperse (bs "&") .
    map (\(Param k v) -> (bs k) <> (bs "=") <> (bs v)) .
    sort . map percent_encode

-- | Create the base string which will be signed
sig_base_string :: ByteString -> ByteString -> ByteString -> ByteString
sig_base_string ps method url = build $ (bs method) <> amp <> url' <> amp <> ps'
    where
        amp = bs "&"
        url' = bs $ percent_encode url
        ps' = bs $ percent_encode ps

-- | Create the OAuth signing key from the various access secrets
signing_key :: ByteString -> Maybe ByteString -> ByteString
signing_key secret token = build $ (bs secret) <> (bs "&") <> token' where
    token' = bs $ maybe "" id token

sign
    :: ByteString -- ^ Signing key
    -> ByteString -- ^ Message to sign
    -> ByteString -- ^ Resulting base64-encoded signature
sign key msg = B64.encode $ hmac hash 64 key msg

-- | Generate the Authorization header given a list of 'Param'
create_header_string :: [Param] -> ByteString
create_header_string params = build $ (bs "OAuth  ") <> str where
    q = bs $ pack ['"']
    encoded = sort $ map percent_encode params
    stringified = map (\(Param k v) -> (bs k) <> (bs "=") <> q <> (bs v) <> q)
                  encoded
    comma'd = intersperse (bs ", ") stringified
    str = foldl (<>) mempty comma'd

-- | Generates the signature for a given request, not the full header
oauth_sig
    :: MonadIO m
    => Credentials
    -> ByteString -- ^ method
    -> ByteString -- ^ url
    -> [Param]    -- ^ any extra parameters
    -> m [Param]
oauth_sig creds method url extras = do
    nonce <- gen_nonce
    ts <- timestamp >>= return . pack . show
    let params = [ Param "oauth_consumer_key" (consumerKey creds)
                 , Param "oauth_nonce" nonce
                 , Param "oauth_timestamp" ts
                 , Param "oauth_signature_method" "HMAC-SHA1"
                 , Param "oauth_version" "1.0"
                 ]
    let sk = signing_key (consumerSecret creds) (tokenSecret creds)
    let params' = param_string $ extras ++ params
    let base_string = sig_base_string params' method url
    let signature = sign sk base_string
    return $ (Param "oauth_signature" signature) : (params ++ extras)

auth_header
    :: MonadIO m
    => Credentials
    -> ByteString -- ^ method
    -> ByteString -- ^ url
    -> [Param]    -- ^ Any extra parameters
    -> m ByteString
auth_header (Credentials key secret token token_secret) method url extras = do
    nonce <- gen_nonce
    ts    <- timestamp >>= return . pack . show
    let params = [ Param "oauth_consumer_key" key
                 , Param "oauth_nonce" nonce
                 , Param "oauth_timestamp" ts
                 , Param "oauth_token" (maybe "" id token)
                 , Param "oauth_signature_method" "HMAC-SHA1"
                 , Param "oauth_version" "1.0"
                 ]
    let sk = signing_key secret token_secret
    let params' = param_string $ extras ++ params
    let base_string = sig_base_string params' method url
    let signature = sign sk base_string
    let with_signature = (Param "oauth_signature" signature) : params
    return $ create_header_string with_signature
