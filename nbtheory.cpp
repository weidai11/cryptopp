// nbtheory.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"

#ifndef CRYPTOPP_IMPORTS

#include "nbtheory.h"
#include "modarith.h"
#include "algparam.h"

#include <math.h>
#include <vector>

NAMESPACE_BEGIN(CryptoPP)

const unsigned int maxPrimeTableSize = 3511;	// last prime 32719
const word lastSmallPrime = 32719;
unsigned int primeTableSize=552;

word primeTable[maxPrimeTableSize] =
	{2, 3, 5, 7, 11, 13, 17, 19,
	23, 29, 31, 37, 41, 43, 47, 53,
	59, 61, 67, 71, 73, 79, 83, 89,
	97, 101, 103, 107, 109, 113, 127, 131,
	137, 139, 149, 151, 157, 163, 167, 173,
	179, 181, 191, 193, 197, 199, 211, 223,
	227, 229, 233, 239, 241, 251, 257, 263,
	269, 271, 277, 281, 283, 293, 307, 311,
	313, 317, 331, 337, 347, 349, 353, 359,
	367, 373, 379, 383, 389, 397, 401, 409,
	419, 421, 431, 433, 439, 443, 449, 457,
	461, 463, 467, 479, 487, 491, 499, 503,
	509, 521, 523, 541, 547, 557, 563, 569,
	571, 577, 587, 593, 599, 601, 607, 613,
	617, 619, 631, 641, 643, 647, 653, 659,
	661, 673, 677, 683, 691, 701, 709, 719,
	727, 733, 739, 743, 751, 757, 761, 769,
	773, 787, 797, 809, 811, 821, 823, 827,
	829, 839, 853, 857, 859, 863, 877, 881,
	883, 887, 907, 911, 919, 929, 937, 941,
	947, 953, 967, 971, 977, 983, 991, 997,
	1009, 1013, 1019, 1021, 1031, 1033, 1039, 1049,
	1051, 1061, 1063, 1069, 1087, 1091, 1093, 1097,
	1103, 1109, 1117, 1123, 1129, 1151, 1153, 1163,
	1171, 1181, 1187, 1193, 1201, 1213, 1217, 1223,
	1229, 1231, 1237, 1249, 1259, 1277, 1279, 1283,
	1289, 1291, 1297, 1301, 1303, 1307, 1319, 1321,
	1327, 1361, 1367, 1373, 1381, 1399, 1409, 1423,
	1427, 1429, 1433, 1439, 1447, 1451, 1453, 1459,
	1471, 1481, 1483, 1487, 1489, 1493, 1499, 1511,
	1523, 1531, 1543, 1549, 1553, 1559, 1567, 1571,
	1579, 1583, 1597, 1601, 1607, 1609, 1613, 1619,
	1621, 1627, 1637, 1657, 1663, 1667, 1669, 1693,
	1697, 1699, 1709, 1721, 1723, 1733, 1741, 1747,
	1753, 1759, 1777, 1783, 1787, 1789, 1801, 1811,
	1823, 1831, 1847, 1861, 1867, 1871, 1873, 1877,
	1879, 1889, 1901, 1907, 1913, 1931, 1933, 1949,
	1951, 1973, 1979, 1987, 1993, 1997, 1999, 2003,
	2011, 2017, 2027, 2029, 2039, 2053, 2063, 2069,
	2081, 2083, 2087, 2089, 2099, 2111, 2113, 2129,
	2131, 2137, 2141, 2143, 2153, 2161, 2179, 2203,
	2207, 2213, 2221, 2237, 2239, 2243, 2251, 2267,
	2269, 2273, 2281, 2287, 2293, 2297, 2309, 2311,
	2333, 2339, 2341, 2347, 2351, 2357, 2371, 2377,
	2381, 2383, 2389, 2393, 2399, 2411, 2417, 2423,
	2437, 2441, 2447, 2459, 2467, 2473, 2477, 2503,
	2521, 2531, 2539, 2543, 2549, 2551, 2557, 2579,
	2591, 2593, 2609, 2617, 2621, 2633, 2647, 2657,
	2659, 2663, 2671, 2677, 2683, 2687, 2689, 2693,
	2699, 2707, 2711, 2713, 2719, 2729, 2731, 2741,
	2749, 2753, 2767, 2777, 2789, 2791, 2797, 2801,
	2803, 2819, 2833, 2837, 2843, 2851, 2857, 2861,
	2879, 2887, 2897, 2903, 2909, 2917, 2927, 2939,
	2953, 2957, 2963, 2969, 2971, 2999, 3001, 3011,
	3019, 3023, 3037, 3041, 3049, 3061, 3067, 3079,
	3083, 3089, 3109, 3119, 3121, 3137, 3163, 3167,
	3169, 3181, 3187, 3191, 3203, 3209, 3217, 3221,
	3229, 3251, 3253, 3257, 3259, 3271, 3299, 3301,
	3307, 3313, 3319, 3323, 3329, 3331, 3343, 3347,
	3359, 3361, 3371, 3373, 3389, 3391, 3407, 3413,
	3433, 3449, 3457, 3461, 3463, 3467, 3469, 3491,
	3499, 3511, 3517, 3527, 3529, 3533, 3539, 3541,
	3547, 3557, 3559, 3571, 3581, 3583, 3593, 3607,
	3613, 3617, 3623, 3631, 3637, 3643, 3659, 3671,
	3673, 3677, 3691, 3697, 3701, 3709, 3719, 3727,
	3733, 3739, 3761, 3767, 3769, 3779, 3793, 3797,
	3803, 3821, 3823, 3833, 3847, 3851, 3853, 3863,
	3877, 3881, 3889, 3907, 3911, 3917, 3919, 3923,
	3929, 3931, 3943, 3947, 3967, 3989, 4001, 4003};

void BuildPrimeTable()
{
	unsigned int p=primeTable[primeTableSize-1];
	for (unsigned int i=primeTableSize; i<maxPrimeTableSize; i++)
	{
		int j;
		do
		{
			p+=2;
			for (j=1; j<54; j++)
				if (p%primeTable[j] == 0)
					break;
		} while (j!=54);
		primeTable[i] = p;
	}
	primeTableSize = maxPrimeTableSize;
	assert(primeTable[primeTableSize-1] == lastSmallPrime);
}

bool IsSmallPrime(const Integer &p)
{
	BuildPrimeTable();

	if (p.IsPositive() && p <= primeTable[primeTableSize-1])
		return std::binary_search(primeTable, primeTable+primeTableSize, (word)p.ConvertToLong());
	else
		return false;
}

bool TrialDivision(const Integer &p, unsigned bound)
{
	assert(primeTable[primeTableSize-1] >= bound);

	unsigned int i;
	for (i = 0; primeTable[i]<bound; i++)
		if ((p % primeTable[i]) == 0)
			return true;

	if (bound == primeTable[i])
		return (p % bound == 0);
	else
		return false;
}

bool SmallDivisorsTest(const Integer &p)
{
	BuildPrimeTable();
	return !TrialDivision(p, primeTable[primeTableSize-1]);
}

bool IsFermatProbablePrime(const Integer &n, const Integer &b)
{
	if (n <= 3)
		return n==2 || n==3;

	assert(n>3 && b>1 && b<n-1);
	return a_exp_b_mod_c(b, n-1, n)==1;
}

bool IsStrongProbablePrime(const Integer &n, const Integer &b)
{
	if (n <= 3)
		return n==2 || n==3;

	assert(n>3 && b>1 && b<n-1);

	if ((n.IsEven() && n!=2) || GCD(b, n) != 1)
		return false;

	Integer nminus1 = (n-1);
	unsigned int a;

	// calculate a = largest power of 2 that divides (n-1)
	for (a=0; ; a++)
		if (nminus1.GetBit(a))
			break;
	Integer m = nminus1>>a;

	Integer z = a_exp_b_mod_c(b, m, n);
	if (z==1 || z==nminus1)
		return true;
	for (unsigned j=1; j<a; j++)
	{
		z = z.Squared()%n;
		if (z==nminus1)
			return true;
		if (z==1)
			return false;
	}
	return false;
}

bool RabinMillerTest(RandomNumberGenerator &rng, const Integer &n, unsigned int rounds)
{
	if (n <= 3)
		return n==2 || n==3;

	assert(n>3);

	Integer b;
	for (unsigned int i=0; i<rounds; i++)
	{
		b.Randomize(rng, 2, n-2);
		if (!IsStrongProbablePrime(n, b))
			return false;
	}
	return true;
}

bool IsLucasProbablePrime(const Integer &n)
{
	if (n <= 1)
		return false;

	if (n.IsEven())
		return n==2;

	assert(n>2);

	Integer b=3;
	unsigned int i=0;
	int j;

	while ((j=Jacobi(b.Squared()-4, n)) == 1)
	{
		if (++i==64 && n.IsSquare())	// avoid infinite loop if n is a square
			return false;
		++b; ++b;
	}

	if (j==0) 
		return false;
	else
		return Lucas(n+1, b, n)==2;
}

bool IsStrongLucasProbablePrime(const Integer &n)
{
	if (n <= 1)
		return false;

	if (n.IsEven())
		return n==2;

	assert(n>2);

	Integer b=3;
	unsigned int i=0;
	int j;

	while ((j=Jacobi(b.Squared()-4, n)) == 1)
	{
		if (++i==64 && n.IsSquare())	// avoid infinite loop if n is a square
			return false;
		++b; ++b;
	}

	if (j==0) 
		return false;

	Integer n1 = n+1;
	unsigned int a;

	// calculate a = largest power of 2 that divides n1
	for (a=0; ; a++)
		if (n1.GetBit(a))
			break;
	Integer m = n1>>a;

	Integer z = Lucas(m, b, n);
	if (z==2 || z==n-2)
		return true;
	for (i=1; i<a; i++)
	{
		z = (z.Squared()-2)%n;
		if (z==n-2)
			return true;
		if (z==2)
			return false;
	}
	return false;
}

bool IsPrime(const Integer &p)
{
	static const Integer lastSmallPrimeSquared = Integer(lastSmallPrime).Squared();

	if (p <= lastSmallPrime)
		return IsSmallPrime(p);
	else if (p <= lastSmallPrimeSquared)
		return SmallDivisorsTest(p);
	else
		return SmallDivisorsTest(p) && IsStrongProbablePrime(p, 3) && IsStrongLucasProbablePrime(p);
}

bool VerifyPrime(RandomNumberGenerator &rng, const Integer &p, unsigned int level)
{
	bool pass = IsPrime(p) && RabinMillerTest(rng, p, 1);
	if (level >= 1)
		pass = pass && RabinMillerTest(rng, p, 10);
	return pass;
}

unsigned int PrimeSearchInterval(const Integer &max)
{
	return max.BitCount();
}

static inline bool FastProbablePrimeTest(const Integer &n)
{
	return IsStrongProbablePrime(n,2);
}

AlgorithmParameters<AlgorithmParameters<AlgorithmParameters<NullNameValuePairs, Integer::RandomNumberType>, Integer>, Integer>
	MakeParametersForTwoPrimesOfEqualSize(unsigned int productBitLength)
{
	if (productBitLength < 16)
		throw InvalidArgument("invalid bit length");

	Integer minP, maxP;

	if (productBitLength%2==0)
	{
		minP = Integer(182) << (productBitLength/2-8);
		maxP = Integer::Power2(productBitLength/2)-1;
	}
	else
	{
		minP = Integer::Power2((productBitLength-1)/2);
		maxP = Integer(181) << ((productBitLength+1)/2-8);
	}

	return MakeParameters("RandomNumberType", Integer::PRIME)("Min", minP)("Max", maxP);
}

class PrimeSieve
{
public:
	// delta == 1 or -1 means double sieve with p = 2*q + delta
	PrimeSieve(const Integer &first, const Integer &last, const Integer &step, signed int delta=0);
	bool NextCandidate(Integer &c);

	void DoSieve();
	static void SieveSingle(std::vector<bool> &sieve, word p, const Integer &first, const Integer &step, word stepInv);

	Integer m_first, m_last, m_step;
	signed int m_delta;
	word m_next;
	std::vector<bool> m_sieve;
};

PrimeSieve::PrimeSieve(const Integer &first, const Integer &last, const Integer &step, signed int delta)
	: m_first(first), m_last(last), m_step(step), m_delta(delta), m_next(0)
{
	DoSieve();
}

bool PrimeSieve::NextCandidate(Integer &c)
{
	m_next = std::find(m_sieve.begin()+m_next, m_sieve.end(), false) - m_sieve.begin();
	if (m_next == m_sieve.size())
	{
		m_first += m_sieve.size()*m_step;
		if (m_first > m_last)
			return false;
		else
		{
			m_next = 0;
			DoSieve();
			return NextCandidate(c);
		}
	}
	else
	{
		c = m_first + m_next*m_step;
		++m_next;
		return true;
	}
}

void PrimeSieve::SieveSingle(std::vector<bool> &sieve, word p, const Integer &first, const Integer &step, word stepInv)
{
	if (stepInv)
	{
		unsigned int sieveSize = sieve.size();
		word j = word((dword(p-(first%p))*stepInv) % p);
		// if the first multiple of p is p, skip it
		if (first.WordCount() <= 1 && first + step*j == p)
			j += p;
		for (; j < sieveSize; j += p)
			sieve[j] = true;
	}
}

void PrimeSieve::DoSieve()
{
	BuildPrimeTable();

	const unsigned int maxSieveSize = 32768;
	unsigned int sieveSize = STDMIN(Integer(maxSieveSize), (m_last-m_first)/m_step+1).ConvertToLong();

	m_sieve.clear();
	m_sieve.resize(sieveSize, false);

	if (m_delta == 0)
	{
		for (unsigned int i = 0; i < primeTableSize; ++i)
			SieveSingle(m_sieve, primeTable[i], m_first, m_step, m_step.InverseMod(primeTable[i]));
	}
	else
	{
		assert(m_step%2==0);
		Integer qFirst = (m_first-m_delta) >> 1;
		Integer halfStep = m_step >> 1;
		for (unsigned int i = 0; i < primeTableSize; ++i)
		{
			word p = primeTable[i];
			word stepInv = m_step.InverseMod(p);
			SieveSingle(m_sieve, p, m_first, m_step, stepInv);

			word halfStepInv = 2*stepInv < p ? 2*stepInv : 2*stepInv-p;
			SieveSingle(m_sieve, p, qFirst, halfStep, halfStepInv);
		}
	}
}

bool FirstPrime(Integer &p, const Integer &max, const Integer &equiv, const Integer &mod, const PrimeSelector *pSelector)
{
	assert(!equiv.IsNegative() && equiv < mod);

	Integer gcd = GCD(equiv, mod);
	if (gcd != Integer::One())
	{
		// the only possible prime p such that p%mod==equiv where GCD(mod,equiv)!=1 is GCD(mod,equiv)
		if (p <= gcd && gcd <= max && IsPrime(gcd))
		{
			p = gcd;
			return true;
		}
		else
			return false;
	}

	BuildPrimeTable();

	if (p <= primeTable[primeTableSize-1])
	{
		word *pItr;

		--p;
		if (p.IsPositive())
			pItr = std::upper_bound(primeTable, primeTable+primeTableSize, (word)p.ConvertToLong());
		else
			pItr = primeTable;

		while (pItr < primeTable+primeTableSize && !(*pItr%mod == equiv && (!pSelector || pSelector->IsAcceptable(*pItr))))
			++pItr;

		if (pItr < primeTable+primeTableSize)
		{
			p = *pItr;
			return p <= max;
		}

		p = primeTable[primeTableSize-1]+1;
	}

	assert(p > primeTable[primeTableSize-1]);

	if (mod.IsOdd())
		return FirstPrime(p, max, CRT(equiv, mod, 1, 2, 1), mod<<1, pSelector);

	p += (equiv-p)%mod;

	if (p>max)
		return false;

	PrimeSieve sieve(p, max, mod);

	while (sieve.NextCandidate(p))
	{
		if ((!pSelector || pSelector->IsAcceptable(p)) && FastProbablePrimeTest(p) && IsPrime(p))
			return true;
	}

	return false;
}

// the following two functions are based on code and comments provided by Preda Mihailescu
static bool ProvePrime(const Integer &p, const Integer &q)
{
	assert(p < q*q*q);
	assert(p % q == 1);

// this is the Quisquater test. Numbers p having passed the Lucas - Lehmer test
// for q and verifying p < q^3 can only be built up of two factors, both = 1 mod q,
// or be prime. The next two lines build the discriminant of a quadratic equation
// which holds iff p is built up of two factors (excercise ... )

	Integer r = (p-1)/q;
	if (((r%q).Squared()-4*(r/q)).IsSquare())
		return false;

	assert(primeTableSize >= 50);
	for (int i=0; i<50; i++) 
	{
		Integer b = a_exp_b_mod_c(primeTable[i], r, p);
		if (b != 1) 
			return a_exp_b_mod_c(b, q, p) == 1;
	}
	return false;
}

Integer MihailescuProvablePrime(RandomNumberGenerator &rng, unsigned int pbits)
{
	Integer p;
	Integer minP = Integer::Power2(pbits-1);
	Integer maxP = Integer::Power2(pbits) - 1;

	if (maxP <= Integer(lastSmallPrime).Squared())
	{
		// Randomize() will generate a prime provable by trial division
		p.Randomize(rng, minP, maxP, Integer::PRIME);
		return p;
	}

	unsigned int qbits = (pbits+2)/3 + 1 + rng.GenerateWord32(0, pbits/36);
	Integer q = MihailescuProvablePrime(rng, qbits);
	Integer q2 = q<<1;

	while (true)
	{
		// this initializes the sieve to search in the arithmetic
		// progression p = p_0 + \lambda * q2 = p_0 + 2 * \lambda * q,
		// with q the recursively generated prime above. We will be able
		// to use Lucas tets for proving primality. A trick of Quisquater
		// allows taking q > cubic_root(p) rather then square_root: this
		// decreases the recursion.

		p.Randomize(rng, minP, maxP, Integer::ANY, 1, q2);
		PrimeSieve sieve(p, STDMIN(p+PrimeSearchInterval(maxP)*q2, maxP), q2);

		while (sieve.NextCandidate(p))
		{
			if (FastProbablePrimeTest(p) && ProvePrime(p, q))
				return p;
		}
	}

	// not reached
	return p;
}

Integer MaurerProvablePrime(RandomNumberGenerator &rng, unsigned int bits)
{
	const unsigned smallPrimeBound = 29, c_opt=10;
	Integer p;

	BuildPrimeTable();
	if (bits < smallPrimeBound)
	{
		do
			p.Randomize(rng, Integer::Power2(bits-1), Integer::Power2(bits)-1, Integer::ANY, 1, 2);
		while (TrialDivision(p, 1 << ((bits+1)/2)));
	}
	else
	{
		const unsigned margin = bits > 50 ? 20 : (bits-10)/2;
		double relativeSize;
		do
			relativeSize = pow(2.0, double(rng.GenerateWord32())/0xffffffff - 1);
		while (bits * relativeSize >= bits - margin);

		Integer a,b;
		Integer q = MaurerProvablePrime(rng, unsigned(bits*relativeSize));
		Integer I = Integer::Power2(bits-2)/q;
		Integer I2 = I << 1;
		unsigned int trialDivisorBound = (unsigned int)STDMIN((unsigned long)primeTable[primeTableSize-1], (unsigned long)bits*bits/c_opt);
		bool success = false;
		while (!success)
		{
			p.Randomize(rng, I, I2, Integer::ANY);
			p *= q; p <<= 1; ++p;
			if (!TrialDivision(p, trialDivisorBound))
			{
				a.Randomize(rng, 2, p-1, Integer::ANY);
				b = a_exp_b_mod_c(a, (p-1)/q, p);
				success = (GCD(b-1, p) == 1) && (a_exp_b_mod_c(b, q, p) == 1);
			}
		}
	}
	return p;
}

Integer CRT(const Integer &xp, const Integer &p, const Integer &xq, const Integer &q, const Integer &u)
{
	// isn't operator overloading great?
	return p * (u * (xq-xp) % q) + xp;
}

Integer CRT(const Integer &xp, const Integer &p, const Integer &xq, const Integer &q)
{
	return CRT(xp, p, xq, q, EuclideanMultiplicativeInverse(p, q));
}

Integer ModularSquareRoot(const Integer &a, const Integer &p)
{
	if (p%4 == 3)
		return a_exp_b_mod_c(a, (p+1)/4, p);

	Integer q=p-1;
	unsigned int r=0;
	while (q.IsEven())
	{
		r++;
		q >>= 1;
	}

	Integer n=2;
	while (Jacobi(n, p) != -1)
		++n;

	Integer y = a_exp_b_mod_c(n, q, p);
	Integer x = a_exp_b_mod_c(a, (q-1)/2, p);
	Integer b = (x.Squared()%p)*a%p;
	x = a*x%p;
	Integer tempb, t;

	while (b != 1)
	{
		unsigned m=0;
		tempb = b;
		do
		{
			m++;
			b = b.Squared()%p;
			if (m==r)
				return Integer::Zero();
		}
		while (b != 1);

		t = y;
		for (unsigned i=0; i<r-m-1; i++)
			t = t.Squared()%p;
		y = t.Squared()%p;
		r = m;
		x = x*t%p;
		b = tempb*y%p;
	}

	assert(x.Squared()%p == a);
	return x;
}

bool SolveModularQuadraticEquation(Integer &r1, Integer &r2, const Integer &a, const Integer &b, const Integer &c, const Integer &p)
{
	Integer D = (b.Squared() - 4*a*c) % p;
	switch (Jacobi(D, p))
	{
	default:
		assert(false);	// not reached
		return false;
	case -1:
		return false;
	case 0:
		r1 = r2 = (-b*(a+a).InverseMod(p)) % p;
		assert(((r1.Squared()*a + r1*b + c) % p).IsZero());
		return true;
	case 1:
		Integer s = ModularSquareRoot(D, p);
		Integer t = (a+a).InverseMod(p);
		r1 = (s-b)*t % p;
		r2 = (-s-b)*t % p;
		assert(((r1.Squared()*a + r1*b + c) % p).IsZero());
		assert(((r2.Squared()*a + r2*b + c) % p).IsZero());
		return true;
	}
}

Integer ModularRoot(const Integer &a, const Integer &dp, const Integer &dq,
					const Integer &p, const Integer &q, const Integer &u)
{
	Integer p2 = ModularExponentiation((a % p), dp, p);
	Integer q2 = ModularExponentiation((a % q), dq, q);
	return CRT(p2, p, q2, q, u);
}

Integer ModularRoot(const Integer &a, const Integer &e,
					const Integer &p, const Integer &q)
{
	Integer dp = EuclideanMultiplicativeInverse(e, p-1);
	Integer dq = EuclideanMultiplicativeInverse(e, q-1);
	Integer u = EuclideanMultiplicativeInverse(p, q);
	assert(!!dp && !!dq && !!u);
	return ModularRoot(a, dp, dq, p, q, u);
}

/*
Integer GCDI(const Integer &x, const Integer &y)
{
	Integer a=x, b=y;
	unsigned k=0;

	assert(!!a && !!b);

	while (a[0]==0 && b[0]==0)
	{
		a >>= 1;
		b >>= 1;
		k++;
	}

	while (a[0]==0)
		a >>= 1;

	while (b[0]==0)
		b >>= 1;

	while (1)
	{
		switch (a.Compare(b))
		{
			case -1:
				b -= a;
				while (b[0]==0)
					b >>= 1;
				break;

			case 0:
				return (a <<= k);

			case 1:
				a -= b;
				while (a[0]==0)
					a >>= 1;
				break;

			default:
				assert(false);
		}
	}
}

Integer EuclideanMultiplicativeInverse(const Integer &a, const Integer &b)
{
	assert(b.Positive());

	if (a.Negative())
		return EuclideanMultiplicativeInverse(a%b, b);

	if (b[0]==0)
	{
		if (!b || a[0]==0)
			return Integer::Zero();       // no inverse
		if (a==1)
			return 1;
		Integer u = EuclideanMultiplicativeInverse(b, a);
		if (!u)
			return Integer::Zero();       // no inverse
		else
			return (b*(a-u)+1)/a;
	}

	Integer u=1, d=a, v1=b, v3=b, t1, t3, b2=(b+1)>>1;

	if (a[0])
	{
		t1 = Integer::Zero();
		t3 = -b;
	}
	else
	{
		t1 = b2;
		t3 = a>>1;
	}

	while (!!t3)
	{
		while (t3[0]==0)
		{
			t3 >>= 1;
			if (t1[0]==0)
				t1 >>= 1;
			else
			{
				t1 >>= 1;
				t1 += b2;
			}
		}
		if (t3.Positive())
		{
			u = t1;
			d = t3;
		}
		else
		{
			v1 = b-t1;
			v3 = -t3;
		}
		t1 = u-v1;
		t3 = d-v3;
		if (t1.Negative())
			t1 += b;
	}
	if (d==1)
		return u;
	else
		return Integer::Zero();   // no inverse
}
*/

int Jacobi(const Integer &aIn, const Integer &bIn)
{
	assert(bIn.IsOdd());

	Integer b = bIn, a = aIn%bIn;
	int result = 1;

	while (!!a)
	{
		unsigned i=0;
		while (a.GetBit(i)==0)
			i++;
		a>>=i;

		if (i%2==1 && (b%8==3 || b%8==5))
			result = -result;

		if (a%4==3 && b%4==3)
			result = -result;

		std::swap(a, b);
		a %= b;
	}

	return (b==1) ? result : 0;
}

Integer Lucas(const Integer &e, const Integer &pIn, const Integer &n)
{
	unsigned i = e.BitCount();
	if (i==0)
		return Integer::Two();

	MontgomeryRepresentation m(n);
	Integer p=m.ConvertIn(pIn%n), two=m.ConvertIn(Integer::Two());
	Integer v=p, v1=m.Subtract(m.Square(p), two);

	i--;
	while (i--)
	{
		if (e.GetBit(i))
		{
			// v = (v*v1 - p) % m;
			v = m.Subtract(m.Multiply(v,v1), p);
			// v1 = (v1*v1 - 2) % m;
			v1 = m.Subtract(m.Square(v1), two);
		}
		else
		{
			// v1 = (v*v1 - p) % m;
			v1 = m.Subtract(m.Multiply(v,v1), p);
			// v = (v*v - 2) % m;
			v = m.Subtract(m.Square(v), two);
		}
	}
	return m.ConvertOut(v);
}

// This is Peter Montgomery's unpublished Lucas sequence evalutation algorithm.
// The total number of multiplies and squares used is less than the binary
// algorithm (see above).  Unfortunately I can't get it to run as fast as
// the binary algorithm because of the extra overhead.
/*
Integer Lucas(const Integer &n, const Integer &P, const Integer &modulus)
{
	if (!n)
		return 2;

#define f(A, B, C)	m.Subtract(m.Multiply(A, B), C)
#define X2(A) m.Subtract(m.Square(A), two)
#define X3(A) m.Multiply(A, m.Subtract(m.Square(A), three))

	MontgomeryRepresentation m(modulus);
	Integer two=m.ConvertIn(2), three=m.ConvertIn(3);
	Integer A=m.ConvertIn(P), B, C, p, d=n, e, r, t, T, U;

	while (d!=1)
	{
		p = d;
		unsigned int b = WORD_BITS * p.WordCount();
		Integer alpha = (Integer(5)<<(2*b-2)).SquareRoot() - Integer::Power2(b-1);
		r = (p*alpha)>>b;
		e = d-r;
		B = A;
		C = two;
		d = r;

		while (d!=e)
		{
			if (d<e)
			{
				swap(d, e);
				swap(A, B);
			}

			unsigned int dm2 = d[0], em2 = e[0];
			unsigned int dm3 = d%3, em3 = e%3;

//			if ((dm6+em6)%3 == 0 && d <= e + (e>>2))
			if ((dm3+em3==0 || dm3+em3==3) && (t = e, t >>= 2, t += e, d <= t))
			{
				// #1
//				t = (d+d-e)/3;
//				t = d; t += d; t -= e; t /= 3;
//				e = (e+e-d)/3;
//				e += e; e -= d; e /= 3;
//				d = t;

//				t = (d+e)/3
				t = d; t += e; t /= 3;
				e -= t;
				d -= t;

				T = f(A, B, C);
				U = f(T, A, B);
				B = f(T, B, A);
				A = U;
				continue;
			}

//			if (dm6 == em6 && d <= e + (e>>2))
			if (dm3 == em3 && dm2 == em2 && (t = e, t >>= 2, t += e, d <= t))
			{
				// #2
//				d = (d-e)>>1;
				d -= e; d >>= 1;
				B = f(A, B, C);
				A = X2(A);
				continue;
			}

//			if (d <= (e<<2))
			if (d <= (t = e, t <<= 2))
			{
				// #3
				d -= e;
				C = f(A, B, C);
				swap(B, C);
				continue;
			}

			if (dm2 == em2)
			{
				// #4
//				d = (d-e)>>1;
				d -= e; d >>= 1;
				B = f(A, B, C);
				A = X2(A);
				continue;
			}

			if (dm2 == 0)
			{
				// #5
				d >>= 1;
				C = f(A, C, B);
				A = X2(A);
				continue;
			}

			if (dm3 == 0)
			{
				// #6
//				d = d/3 - e;
				d /= 3; d -= e;
				T = X2(A);
				C = f(T, f(A, B, C), C);
				swap(B, C);
				A = f(T, A, A);
				continue;
			}

			if (dm3+em3==0 || dm3+em3==3)
			{
				// #7
//				d = (d-e-e)/3;
				d -= e; d -= e; d /= 3;
				T = f(A, B, C);
				B = f(T, A, B);
				A = X3(A);
				continue;
			}

			if (dm3 == em3)
			{
				// #8
//				d = (d-e)/3;
				d -= e; d /= 3;
				T = f(A, B, C);
				C = f(A, C, B);
				B = T;
				A = X3(A);
				continue;
			}

			assert(em2 == 0);
			// #9
			e >>= 1;
			C = f(C, B, A);
			B = X2(B);
		}

		A = f(A, B, C);
	}

#undef f
#undef X2
#undef X3

	return m.ConvertOut(A);
}
*/

Integer InverseLucas(const Integer &e, const Integer &m, const Integer &p, const Integer &q, const Integer &u)
{
	Integer d = (m*m-4);
	Integer p2 = p-Jacobi(d,p);
	Integer q2 = q-Jacobi(d,q);
	return CRT(Lucas(EuclideanMultiplicativeInverse(e,p2), m, p), p, Lucas(EuclideanMultiplicativeInverse(e,q2), m, q), q, u);
}

Integer InverseLucas(const Integer &e, const Integer &m, const Integer &p, const Integer &q)
{
	return InverseLucas(e, m, p, q, EuclideanMultiplicativeInverse(p, q));
}

unsigned int FactoringWorkFactor(unsigned int n)
{
	// extrapolated from the table in Odlyzko's "The Future of Integer Factorization"
	// updated to reflect the factoring of RSA-130
	if (n<5) return 0;
	else return (unsigned int)(2.4 * pow((double)n, 1.0/3.0) * pow(log(double(n)), 2.0/3.0) - 5);
}

unsigned int DiscreteLogWorkFactor(unsigned int n)
{
	// assuming discrete log takes about the same time as factoring
	if (n<5) return 0;
	else return (unsigned int)(2.4 * pow((double)n, 1.0/3.0) * pow(log(double(n)), 2.0/3.0) - 5);
}

// ********************************************************

void PrimeAndGenerator::Generate(signed int delta, RandomNumberGenerator &rng, unsigned int pbits, unsigned int qbits)
{
	// no prime exists for delta = -1, qbits = 4, and pbits = 5
	assert(qbits > 4);
	assert(pbits > qbits);

	if (qbits+1 == pbits)
	{
		Integer minP = Integer::Power2(pbits-1);
		Integer maxP = Integer::Power2(pbits) - 1;
		bool success = false;

		while (!success)
		{
			p.Randomize(rng, minP, maxP, Integer::ANY, 6+5*delta, 12);
			PrimeSieve sieve(p, STDMIN(p+PrimeSearchInterval(maxP)*12, maxP), 12, delta);

			while (sieve.NextCandidate(p))
			{
				assert(IsSmallPrime(p) || SmallDivisorsTest(p));
				q = (p-delta) >> 1;
				assert(IsSmallPrime(q) || SmallDivisorsTest(q));
				if (FastProbablePrimeTest(q) && FastProbablePrimeTest(p) && IsPrime(q) && IsPrime(p))
				{
					success = true;
					break;
				}
			}
		}

		if (delta == 1)
		{
			// find g such that g is a quadratic residue mod p, then g has order q
			// g=4 always works, but this way we get the smallest quadratic residue (other than 1)
			for (g=2; Jacobi(g, p) != 1; ++g) {}
			// contributed by Walt Tuvell: g should be the following according to the Law of Quadratic Reciprocity
			assert((p%8==1 || p%8==7) ? g==2 : (p%12==1 || p%12==11) ? g==3 : g==4);
		}
		else
		{
			assert(delta == -1);
			// find g such that g*g-4 is a quadratic non-residue, 
			// and such that g has order q
			for (g=3; ; ++g)
				if (Jacobi(g*g-4, p)==-1 && Lucas(q, g, p)==2)
					break;
		}
	}
	else
	{
		Integer minQ = Integer::Power2(qbits-1);
		Integer maxQ = Integer::Power2(qbits) - 1;
		Integer minP = Integer::Power2(pbits-1);
		Integer maxP = Integer::Power2(pbits) - 1;

		do
		{
			q.Randomize(rng, minQ, maxQ, Integer::PRIME);
		} while (!p.Randomize(rng, minP, maxP, Integer::PRIME, delta%q, q));

		// find a random g of order q
		if (delta==1)
		{
			do
			{
				Integer h(rng, 2, p-2, Integer::ANY);
				g = a_exp_b_mod_c(h, (p-1)/q, p);
			} while (g <= 1);
			assert(a_exp_b_mod_c(g, q, p)==1);
		}
		else
		{
			assert(delta==-1);
			do
			{
				Integer h(rng, 3, p-1, Integer::ANY);
				if (Jacobi(h*h-4, p)==1)
					continue;
				g = Lucas((p+1)/q, h, p);
			} while (g <= 2);
			assert(Lucas(q, g, p) == 2);
		}
	}
}

NAMESPACE_END

#endif
