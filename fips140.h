#ifndef CRYPTOPP_FIPS140_H
#define CRYPTOPP_FIPS140_H

/*! \file
	FIPS 140 related functions and classes.
*/

#include "cryptlib.h"

NAMESPACE_BEGIN(CryptoPP)

//! exception thrown when a crypto algorithm is used after a self test fails
class SelfTestFailure : public Exception
{
public:
	explicit SelfTestFailure(const std::string &s) : Exception(OTHER_ERROR, s) {}
};

//! returns whether FIPS 140-2 compliance features were enabled at compile time
bool FIPS_140_2_ComplianceEnabled();

//! enum values representing status of the power-up self test
enum PowerUpSelfTestStatus {POWER_UP_SELF_TEST_NOT_DONE, POWER_UP_SELF_TEST_FAILED, POWER_UP_SELF_TEST_PASSED};

//! perform the power-up self test, and set the self test status
void DoPowerUpSelfTest(const char *moduleFilename, const byte *expectedModuleSha1Digest);

//! set the power-up self test status to POWER_UP_SELF_TEST_FAILED
void SimulatePowerUpSelfTestFailure();

//! return the current power-up self test status
PowerUpSelfTestStatus GetPowerUpSelfTestStatus();

// this is used by Algorithm constructor to allow Algorithm objects to be constructed for the self test
bool PowerUpSelfTestInProgressOnThisThread();

void SetPowerUpSelfTestInProgressOnThisThread(bool inProgress);

void SignaturePairwiseConsistencyTest(const PK_Signer &signer, const PK_Verifier &verifier);
void EncryptionPairwiseConsistencyTest(const PK_Encryptor &encryptor, const PK_Decryptor &decryptor);

void SignaturePairwiseConsistencyTest_FIPS_140_Only(const PK_Signer &signer, const PK_Verifier &verifier);
void EncryptionPairwiseConsistencyTest_FIPS_140_Only(const PK_Encryptor &encryptor, const PK_Decryptor &decryptor);

NAMESPACE_END

#endif
