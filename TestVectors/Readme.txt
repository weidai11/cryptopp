Test Data Format

A test data file is an ASCII text file composed of sections separated by 
blank lines. Each section is stand-alone and independent of other 
sections that may be in the same file, and contains one or more tests.

A section is composed of a sequence of fields. Each field is one or more 
lines composed of a field name, followed by a colon (":"), followed by a 
field body. All but the last line of a field must end with a backslash 
("\"). If any line contains a hash mark ("#"), the hash mark and 
everything after it on the same line is not considered part of the field 
body.

Each section must contain fields named AlgorithmType, Name, Source, and 
Test. The presence and semantics of other fields depend on the algorithm 
being tested and the tests to be run. 

Each section may contain more than one test and therefore more than one 
field named Test. In that case the order of the fields is significant. A 
test should always use the last field with any given name that occurs 
before the Test field.

Format and Semantics of Fields

AlgorithmType - string, for example "Signature", "AsymmetricCipher", 
"SymmetricCipher", "MAC", "MessageDigest", or "KeyFactory"
Name - string, an algorithm name from SCAN
Test - string, identifies the test to run
Source - string, text explaining where the test data came from
Comment - string, other comments about the test data
KeyFormat - string, specifies the key format. "Component" here means 
each component of the key or key pair is specified separately as a name, 
value pair, with the names depending on the algorithm being tested. 
Otherwise the value names "Key", or "PublicKey" and "PrivateKey" are 
used.
Key - hex encoded string
PublicKey - hex encoded string
PrivateKey - hex encoded string
Message - hex encoded string, message to be signed or verified
Signature - hex encoded string, signature to be verified or compared 
with
Plaintext - hex encoded string
Ciphertext - hex encoded string
(more to come here)

Possible Tests

KeyPairValidAndConsistent - public and private keys are both valid and 
consistent with each other
PublicKeyInvalid - public key validation should not pass
PrivateKeyInvalid - private key validation should not pass
Verify - signature verification should pass
NotVerify - signature verification should not pass
DeterministicSign - sign message using given seed, and the resulting 
signature should be equal to the given signature
DecryptMatch - ciphertext decrypts to plaintext
(more to come here)
