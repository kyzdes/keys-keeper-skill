"""SigV4 signer locked against the official AWS aws-sig-v4-test-suite vector
`get-vanilla`. If any of these byte-equality asserts fail, the signer is broken
— do not relax them. (F23)
"""
from keys_keeper.backend import Sealed
from keys_keeper.sync_remote import S3Signer, uri_encode, encode_query

# Official suite credentials/date.
_AKID = "AKIDEXAMPLE"
_SECRET = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
_DATE = "20150830T123600Z"

_EXPECTED_CR = (
    "GET\n"
    "/\n"
    "\n"
    "host:example.amazonaws.com\n"
    "x-amz-date:20150830T123600Z\n"
    "\n"
    "host;x-amz-date\n"
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)
_EXPECTED_HCR = "bb579772317eb040ac9ed261061d46c1f17a8133879d6129b6e1c25292927e63"
_EXPECTED_KSIGN = "938127b5336810ddb6a5d6af445fcac9e371f9ed418ed386b022aed82901be75"
_EXPECTED_SIG = "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
_EXPECTED_AUTH = (
    "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, "
    "SignedHeaders=host;x-amz-date, "
    "Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
)


def _signer(service="service", region="us-east-1"):
    return S3Signer(_AKID, Sealed(_SECRET), region=region, service=service)


def test_F23_get_vanilla_known_answer_vector():
    p = _signer().components(
        "GET", "/", {}, {"host": "example.amazonaws.com"}, b"", amz_date=_DATE
    )
    assert p.canonical_request == _EXPECTED_CR
    assert p.hashed_canonical_request == _EXPECTED_HCR
    assert p.signing_key.hex() == _EXPECTED_KSIGN
    assert p.signature == _EXPECTED_SIG
    assert p.authorization == _EXPECTED_AUTH


def test_secret_never_appears_in_signed_output():
    p = _signer().components(
        "GET", "/", {}, {"host": "example.amazonaws.com"}, b"", amz_date=_DATE
    )
    # S5: only the derived signature leaves the envelope, never the secret bytes.
    assert _SECRET not in p.authorization
    assert _SECRET not in p.canonical_request
    assert _SECRET not in p.string_to_sign


def test_uri_encode_rules():
    assert uri_encode("/bucket/kk/versions/000042.json", encode_slash=False) == \
        "/bucket/kk/versions/000042.json"
    assert uri_encode("a b", encode_slash=True) == "a%20b"       # space -> %20
    assert uri_encode("a/b", encode_slash=True) == "a%2Fb"       # slash encoded in query
    assert uri_encode("~-._", encode_slash=True) == "~-._"       # unreserved untouched


def test_encode_query_sorted_and_encoded():
    assert encode_query({"prefix": "kk/versions/", "list-type": "2"}) == \
        "list-type=2&prefix=kk%2Fversions%2F"
    assert encode_query({}) == ""


def test_signature_deterministic_for_slashed_s3_key():
    """Regression lock: an S3 PUT to a slashed key signs deterministically and
    the secret stays out of the output. (Value frozen from our own signer once
    the get-vanilla vector above passes.)"""
    headers = {
        "host": "bucket.s3.amazonaws.com",
        "x-amz-content-sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    }
    p = _signer(service="s3", region="us-east-1").components(
        "PUT", "/bucket/kk/versions/000042.json", {}, headers, b"", amz_date=_DATE
    )
    # path encoded exactly once (slashes preserved), x-amz-content-sha256 signed
    assert "/bucket/kk/versions/000042.json" in p.canonical_request
    assert p.signed_headers == "host;x-amz-content-sha256;x-amz-date"
    assert _SECRET not in p.authorization
    # determinism
    p2 = _signer(service="s3").components(
        "PUT", "/bucket/kk/versions/000042.json", {}, headers, b"", amz_date=_DATE
    )
    assert p.signature == p2.signature
