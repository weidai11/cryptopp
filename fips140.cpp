// fips140.cpp - originally written and placed in the public domain by Wei Dai

#include "pch.h"

#ifndef CRYPTOPP_IMPORTS

#include "fips140.h"
#include "misc.h"

NAMESPACE_BEGIN(CryptoPP)

// Define this to 1 to turn on FIPS 140-2 compliance features, including additional tests during
// startup, random number generation, and key generation. These tests may affect performance.
#ifndef CRYPTOPP_ENABLE_COMPLIANCE_WITH_FIPS_140_2
#define CRYPTOPP_ENABLE_COMPLIANCE_WITH_FIPS_140_2 0
#endif

#if (CRYPTOPP_ENABLE_COMPLIANCE_WITH_FIPS_140_2 && !defined(OS_RNG_AVAILABLE))
#error FIPS 140-2 compliance requires the availability of OS provided RNG.
#endif

PowerUpSelfTestStatus g_powerUpSelfTestStatus = POWER_UP_SELF_TEST_NOT_DONE;

bool FIPS_140_2_ComplianceEnabled()
{
	return CRYPTOPP_ENABLE_COMPLIANCE_WITH_FIPS_140_2;
}

void SimulatePowerUpSelfTestFailure()
{
	g_powerUpSelfTestStatus = POWER_UP_SELF_TEST_FAILED;
}

PowerUpSelfTestStatus CRYPTOPP_API GetPowerUpSelfTestStatus()
{
	return g_powerUpSelfTestStatus;
}

// One variable for all threads for compatibility. Previously this
// was a ThreadLocalStorage variable, which is per-thread. Also see
// https://github.com/weidai11/cryptopp/issues/208
static bool s_inProgress = false;

bool PowerUpSelfTestInProgressOnThisThread()
{
#if CRYPTOPP_ENABLE_COMPLIANCE_WITH_FIPS_140_2
	return s_inProgress;
#endif
	return false;
}

void SetPowerUpSelfTestInProgressOnThisThread(bool inProgress)
{
	CRYPTOPP_UNUSED(inProgress);
#if CRYPTOPP_ENABLE_COMPLIANCE_WITH_FIPS_140_2
	s_inProgress = inProgress;
#endif
}

void EncryptionPairwiseConsistencyTest_FIPS_140_Only(const PK_Encryptor &encryptor, const PK_Decryptor &decryptor)
{
	CRYPTOPP_UNUSED(encryptor), CRYPTOPP_UNUSED(decryptor);
#if CRYPTOPP_ENABLE_COMPLIANCE_WITH_FIPS_140_2
	EncryptionPairwiseConsistencyTest(encryptor, decryptor);
#endif
}

void SignaturePairwiseConsistencyTest_FIPS_140_Only(const PK_Signer &signer, const PK_Verifier &verifier)
{
	CRYPTOPP_UNUSED(signer), CRYPTOPP_UNUSED(verifier);
#if CRYPTOPP_ENABLE_COMPLIANCE_WITH_FIPS_140_2
	SignaturePairwiseConsistencyTest(signer, verifier);
#endif
}

NAMESPACE_END

#endif
