// secblock.h - written and placed in the public domain by Wei Dai

#ifndef CRYPTOPP_SECBLOCK_H
#define CRYPTOPP_SECBLOCK_H

#include "config.h"
#include "stdcpp.h"
#include "misc.h"

#if GCC_DIAGNOSTIC_AWARE
# pragma GCC diagnostic push
# pragma GCC diagnostic ignored "-Wunused-value"
# pragma GCC diagnostic ignored "-Wunused-variable"
# pragma GCC diagnostic ignored "-Wunused-parameter"
#endif

NAMESPACE_BEGIN(CryptoPP)

// ************** secure memory allocation ***************

template<class T>
class AllocatorBase
{
public:
	typedef T value_type;
	typedef size_t size_type;
#ifdef CRYPTOPP_MSVCRT6
	typedef ptrdiff_t difference_type;
#else
	typedef std::ptrdiff_t difference_type;
#endif
	typedef T * pointer;
	typedef const T * const_pointer;
	typedef T & reference;
	typedef const T & const_reference;

	pointer address(reference r) const {return (&r);}
	const_pointer address(const_reference r) const {return (&r); }
	void construct(pointer p, const T& val) {new (p) T(val);}
	void destroy(pointer p) {p->~T();}
	size_type max_size() const {return std::numeric_limits<size_type>::max()/sizeof(T);}

protected:
	static void CheckSize(size_t n)
	{
		if (n > std::numeric_limits<CPP_TYPENAME AllocatorBase::size_type>::max() / sizeof(T))
			throw InvalidArgument("AllocatorBase: requested size would cause integer overflow");
	}
};

#define CRYPTOPP_INHERIT_ALLOCATOR_TYPES	\
typedef typename AllocatorBase<T>::value_type value_type;\
typedef typename AllocatorBase<T>::size_type size_type;\
typedef typename AllocatorBase<T>::difference_type difference_type;\
typedef typename AllocatorBase<T>::pointer pointer;\
typedef typename AllocatorBase<T>::const_pointer const_pointer;\
typedef typename AllocatorBase<T>::reference reference;\
typedef typename AllocatorBase<T>::const_reference const_reference;

#if defined(_MSC_VER) && (_MSC_VER < 1300)
// this pragma causes an internal compiler error if placed immediately before std::swap(a, b)
#pragma warning(push)
#pragma warning(disable: 4700)	// VC60 workaround: don't know how to get rid of this warning
#endif

template <class T, class A>
typename A::pointer StandardReallocate(A& a, T *p, typename A::size_type oldSize, typename A::size_type newSize, bool preserve)
{
	if (oldSize == newSize)
		return p;

	if (preserve)
	{
		typename A::pointer newPointer = a.allocate(newSize, NULL);
		const size_t copySize = STDMIN(oldSize, newSize);
		if(p && copySize) {memcpy_s(newPointer, newSize*sizeof(T), p, copySize*sizeof(T));}
		a.deallocate(p, oldSize);
		return newPointer;
	}
	else
	{
		a.deallocate(p, oldSize);
		return a.allocate(newSize, NULL);
	}
}

#if defined(_MSC_VER) && (_MSC_VER < 1300)
#pragma warning(pop)
#endif

template <class T, bool T_Align16 = false>
class AllocatorWithCleanup : public AllocatorBase<T>
{
public:
	CRYPTOPP_INHERIT_ALLOCATOR_TYPES

	pointer allocate(size_type n, const void * = NULL)
	{
		this->CheckSize(n);
		if (n == 0)
			return NULL;

#if CRYPTOPP_BOOL_ALIGN16_ENABLED
		if (T_Align16 && n*sizeof(T) >= 16)
			return (pointer)AlignedAllocate(n*sizeof(T));
#endif

		return (pointer)UnalignedAllocate(n*sizeof(T));
	}

	void deallocate(void *p, size_type n)
	{	CRYPTOPP_ASSERT((p && n) || (!p && !n));
		SecureWipeArray((pointer)p, n);
		// CRYPTOPP_ASSERT((n == 0) || (n > 0 && ((T*)p)[0] == 0));
		// CRYPTOPP_ASSERT((n == 0) || (n > 0 && ((T*)p)[sizeof(T)*n-1] == 0));

#if CRYPTOPP_BOOL_ALIGN16_ENABLED
		if (T_Align16 && n*sizeof(T) >= 16)
			return AlignedDeallocate(p);
#endif

		UnalignedDeallocate(p);
	}

	pointer reallocate(T *p, size_type oldSize, size_type newSize, bool preserve)
	{
		return StandardReallocate(*this, p, oldSize, newSize, preserve);
	}

	// VS.NET STL enforces the policy of "All STL-compliant allocators have to provide a
	// template class member called rebind".
    template <class U> struct rebind { typedef AllocatorWithCleanup<U, T_Align16> other; };
#if _MSC_VER >= 1500
	AllocatorWithCleanup() {}
	template <class U, bool A> AllocatorWithCleanup(const AllocatorWithCleanup<U, A> &) {}
#endif
};

CRYPTOPP_DLL_TEMPLATE_CLASS AllocatorWithCleanup<byte>;
CRYPTOPP_DLL_TEMPLATE_CLASS AllocatorWithCleanup<word16>;
CRYPTOPP_DLL_TEMPLATE_CLASS AllocatorWithCleanup<word32>;
CRYPTOPP_DLL_TEMPLATE_CLASS AllocatorWithCleanup<word64>;
#if CRYPTOPP_BOOL_X86
CRYPTOPP_DLL_TEMPLATE_CLASS AllocatorWithCleanup<word, true>;	// for Integer
#endif

template <class T>
class NullAllocator : public AllocatorBase<T>
{
public:
	CRYPTOPP_INHERIT_ALLOCATOR_TYPES

	pointer allocate(size_type n, const void * = NULL)
	{
		CRYPTOPP_ASSERT(false);
		return NULL;
	}

	void deallocate(void *p, size_type n)
	{
		CRYPTOPP_ASSERT(false);
	}

	size_type max_size() const {return 0;}
};

// This allocator can't be used with standard collections because
// they require that all objects of the same allocator type are equivalent.
// So this is for use with SecBlock only.
template <class T, size_t S, class A = NullAllocator<T>, bool T_Align16 = false>
class FixedSizeAllocatorWithCleanup : public AllocatorBase<T>
{
public:
	CRYPTOPP_INHERIT_ALLOCATOR_TYPES

	FixedSizeAllocatorWithCleanup() : m_allocated(false) {}

	pointer allocate(size_type n)
	{
		CRYPTOPP_ASSERT(IsAlignedOn(m_array, 8));

		if (n <= S && !m_allocated)
		{
			m_allocated = true;
			return GetAlignedArray();
		}
		else
			return m_fallbackAllocator.allocate(n);
	}

	pointer allocate(size_type n, const void *hint)
	{
		if (n <= S && !m_allocated)
		{
			m_allocated = true;
			return GetAlignedArray();
		}
		else
			return m_fallbackAllocator.allocate(n, hint);
	}

	void deallocate(void *p, size_type n)
	{
		if (p == GetAlignedArray())
		{
			CRYPTOPP_ASSERT(n <= S);
			CRYPTOPP_ASSERT(m_allocated);
			m_allocated = false;
			SecureWipeArray((pointer)p, n);
			// CRYPTOPP_ASSERT((n == 0) || (n > 0 && ((T*)p)[0] == 0));
			// CRYPTOPP_ASSERT((n == 0) || (n > 0 && ((T*)p)[sizeof(T)*n-1] == 0));
		}
		else
			m_fallbackAllocator.deallocate(p, n);
	}

	pointer reallocate(pointer p, size_type oldSize, size_type newSize, bool preserve)
	{
		if (p == GetAlignedArray() && newSize <= S)
		{
			CRYPTOPP_ASSERT(oldSize <= S);
			if (oldSize > newSize)
				SecureWipeArray(p+newSize, oldSize-newSize);
			return p;
		}

		pointer newPointer = allocate(newSize, NULL);
		if (preserve && newSize)
			memcpy_s(newPointer, newSize*sizeof(T), p, sizeof(T)*STDMIN(oldSize, newSize));
		deallocate(p, oldSize);
		return newPointer;
	}

	size_type max_size() const {return STDMAX(m_fallbackAllocator.max_size(), S);}

private:
#ifdef __BORLANDC__
	T* GetAlignedArray() {return m_array;}
	T m_array[S];
#else
	T* GetAlignedArray() {return (CRYPTOPP_BOOL_ALIGN16_ENABLED && T_Align16) ? (T*)(((byte *)m_array) + (0-(size_t)m_array)%16) : m_array;}
	CRYPTOPP_ALIGN_DATA(8) T m_array[(CRYPTOPP_BOOL_ALIGN16_ENABLED && T_Align16) ? S+8/sizeof(T) : S];
#endif
	A m_fallbackAllocator;
	bool m_allocated;
};

//! a block of memory allocated using A
template <class T, class A = AllocatorWithCleanup<T> >
class SecBlock
{
public:
	typedef typename A::value_type value_type;
	typedef typename A::pointer iterator;
	typedef typename A::const_pointer const_iterator;
	typedef typename A::size_type size_type;

	//! construct a SecBlock with space for 'size' elements. To initialize the elements to 0, create a SecBlock and then call CleanNew or CleanGrow.
	explicit SecBlock(size_type size=0)
		: m_size(size), m_ptr(m_alloc.allocate(size, NULL)) { }
	//! copy construct a SecBlock from another SecBlock
	SecBlock(const SecBlock<T, A> &t)
		: m_size(t.m_size), m_ptr(m_alloc.allocate(m_size, NULL)) {
			CRYPTOPP_ASSERT((!t.m_ptr && !m_size) || (t.m_ptr && m_size));
			if(t.m_ptr && t.m_size){memcpy_s(m_ptr,m_size*sizeof(T),t.m_ptr, m_size*sizeof(T));}
		}
	//! construct a SecBlock from an array of elements
	SecBlock(const T *t, size_type len)
		: m_size(len), m_ptr(m_alloc.allocate(m_size, NULL)) {
			CRYPTOPP_ASSERT((!m_ptr && !m_size) || (m_ptr && m_size));
			if(m_ptr && m_size){memcpy_s(m_ptr,m_size*sizeof(T),t,m_size*sizeof(T));}
		}

#if (CRYPTOPP_CXX11_RVALUES && CRYPTOPP_CXX11_MOVE)
	SecBlock(SecBlock&& t)
		: m_alloc(std::move(t.m_alloc)), m_size(t.m_size), m_ptr(std::move(t.m_ptr))
	{
		// TODO: research the move on the Allocator, and remove it if not needed.
		t.m_alloc = A();
		t.m_size = 0;
		t.m_ptr = NULL;
	}
	SecBlock& operator=(SecBlock&& t)
	{
		swap(t);
		return *this;
	}
#endif

	~SecBlock()
		{m_alloc.deallocate(m_ptr, m_size);}

#ifdef __BORLANDC__
	operator T *() const
		{return (T*)m_ptr;}
#else
	operator const void *() const
		{return m_ptr;}
	operator void *()
		{return m_ptr;}

	operator const T *() const
		{return m_ptr;}
	operator T *()
		{return m_ptr;}
#endif

	//! provide an iterator to the first element of the array
	iterator begin()
		{return m_ptr;}
	//! provide a constant iterator to the first element of the array
	const_iterator begin() const
		{return m_ptr;}
	//! provide an iterator set beyond the last element of the array
	iterator end()
		{return m_ptr+m_size;}
	//! provide a constant iterator set beyond the last element of the array
	const_iterator end() const
		{return m_ptr+m_size;}

	//! return a pointer to the first element in the array
	typename A::pointer data() {return m_ptr;}
	//! return a constant pointer to the first element in the array
	typename A::const_pointer data() const {return m_ptr;}

	//! return the number of elements in the array
	size_type size() const {return m_size;}
	//! return the number of elements in the array
	bool empty() const {return m_size == 0;}

	//! return a byte pointer to the first element in the array
	byte * BytePtr() {return (byte *)m_ptr;}
	//! return a byte pointer to the first element in the array
	const byte * BytePtr() const {return (const byte *)m_ptr;}
	//! return the number of bytes in the array
	size_type SizeInBytes() const {return m_size*sizeof(T);}

	//! set contents and size from an array
	void Assign(const T *t, size_type len)
	{
		// if the array is reduced in size, then the unused area is set to 0
		New(len);
		if(t && len) {memcpy_s(m_ptr,m_size*sizeof(T),t,len*sizeof(T));}
	}

	//! copy contents and size from another SecBlock
	void Assign(const SecBlock<T, A> &t)
	{
		if (this != &t)
		{
			// if the array is reduced in size, then the unused area is set to 0
			New(t.m_size);
			if(t.m_ptr && t.m_size) {memcpy_s(m_ptr,m_size*sizeof(T),t.m_ptr,t.m_size*sizeof(T));}
		}
	}

	//! assign contents and size from another SecBlock
	SecBlock<T, A>& operator=(const SecBlock<T, A> &t)
	{
		// Assign guards for self-assignment
		Assign(t);
		return *this;
	}

	// append to this object
	SecBlock<T, A>& operator+=(const SecBlock<T, A> &t)
	{
		CRYPTOPP_ASSERT((!t.m_ptr && !t.m_size) || (t.m_ptr && t.m_size));

		size_type oldSize = m_size;
		Grow(m_size+t.m_size);
		if(t.m_ptr && t.m_size) {memcpy_s(m_ptr+oldSize, (m_size - oldSize)*sizeof(T), t.m_ptr, t.m_size*sizeof(T));}
		return *this;
	}

	// append operator
	SecBlock<T, A> operator+(const SecBlock<T, A> &t)
	{
		CRYPTOPP_ASSERT((!m_ptr && !m_size) || (m_ptr && m_size));
		CRYPTOPP_ASSERT((!t.m_ptr && !t.m_size) || (t.m_ptr && t.m_size));

		SecBlock<T, A> result(m_size+t.m_size);
		if(m_ptr && m_size) {memcpy_s(result.m_ptr, result.m_size*sizeof(T), m_ptr, m_size*sizeof(T));}
		if(t.m_ptr && t.m_size) {memcpy_s(result.m_ptr+m_size, (result.m_size - m_size)*sizeof(T), t.m_ptr, t.m_size*sizeof(T));}
		return result;
	}

	//! bitwise compare two SecBlocks using a constant time compare if the arrays are equal size
	bool operator==(const SecBlock<T, A> &t) const
	{
		return m_size == t.m_size && VerifyBufsEqual(m_ptr, t.m_ptr, m_size*sizeof(T));
	}

	//! bitwise compare two SecBlocks using a constant time compare if the arrays are equal size
	bool operator!=(const SecBlock<T, A> &t) const
	{
		return !operator==(t);
	}

	//! change size without preserving contents, new content unintialized
	void New(size_type newSize)
	{
		// if the array is reduced in size, then the unused area is set to 0
		m_ptr = m_alloc.reallocate(m_ptr, m_size, newSize, false);
		m_size = newSize;
	}

	//! change size without preserving contents. all content set to 0
	void CleanNew(size_type newSize)
	{
		New(newSize);
		memset_z(m_ptr, 0, m_size*sizeof(T));
	}

	//! change size only if newSize > current size. contents are preserved, new content unintialized
	void Grow(size_type newSize)
	{
		if (newSize > m_size)
		{
			m_ptr = m_alloc.reallocate(m_ptr, m_size, newSize, true);
			m_size = newSize;
		}
	}

	//! change size only if newSize > current size. contents are preserved, new content set to 0
	void CleanGrow(size_type newSize)
	{
		if (newSize > m_size)
		{
			m_ptr = m_alloc.reallocate(m_ptr, m_size, newSize, true);
			memset_z(m_ptr+m_size, 0, (newSize-m_size)*sizeof(T));
			m_size = newSize;
		}
	}

	//! change size and preserve contents. new content is uninitialized.
	void resize(size_type newSize)
	{
		m_ptr = m_alloc.reallocate(m_ptr, m_size, newSize, true);
		m_size = newSize;
	}

	//! swap contents and size with another SecBlock
	void swap(SecBlock<T, A> &b)
	{
		// TODO: research the swap on the Allocator, and remove it if not needed.
		std::swap(m_alloc, b.m_alloc);
		std::swap(m_size, b.m_size);
		std::swap(m_ptr, b.m_ptr);
	}

protected:
	A m_alloc;
	size_type m_size;
	T *m_ptr;
};

DOCUMENTED_TYPEDEF(SecBlock<byte>, SecByteBlock);
DOCUMENTED_TYPEDEF(SecBlock<word>, SecWordBlock);
// typedef SecBlock<byte> SecByteBlock;
typedef SecBlock<byte, AllocatorWithCleanup<byte, true> > AlignedSecByteBlock;
// typedef SecBlock<word> SecWordBlock;

// No need for move semantics on derived class *if* the class does not add any
//   data members; see http://stackoverflow.com/q/31755703, and Rule of {0|3|5}.

//! a SecBlock with fixed size, allocated statically
template <class T, unsigned int S, class A = FixedSizeAllocatorWithCleanup<T, S> >
class FixedSizeSecBlock : public SecBlock<T, A>
{
public:
	//! construct a FixedSizeSecBlock
	explicit FixedSizeSecBlock() : SecBlock<T, A>(S) {}
};

template <class T, unsigned int S, bool T_Align16 = true>
class FixedSizeAlignedSecBlock : public FixedSizeSecBlock<T, S, FixedSizeAllocatorWithCleanup<T, S, NullAllocator<T>, T_Align16> >
{
};

//! a SecBlock that preallocates size S statically, and uses the heap when this size is exceeded
template <class T, unsigned int S, class A = FixedSizeAllocatorWithCleanup<T, S, AllocatorWithCleanup<T> > >
class SecBlockWithHint : public SecBlock<T, A>
{
public:
	//! construct a SecBlockWithHint with a count of elements
	explicit SecBlockWithHint(size_t size) : SecBlock<T, A>(size) {}
};

template<class T, bool A, class U, bool B>
inline bool operator==(const CryptoPP::AllocatorWithCleanup<T, A>&, const CryptoPP::AllocatorWithCleanup<U, B>&) {return (true);}
template<class T, bool A, class U, bool B>
inline bool operator!=(const CryptoPP::AllocatorWithCleanup<T, A>&, const CryptoPP::AllocatorWithCleanup<U, B>&) {return (false);}

NAMESPACE_END

NAMESPACE_BEGIN(std)
template <class T, class A>
inline void swap(CryptoPP::SecBlock<T, A> &a, CryptoPP::SecBlock<T, A> &b)
{
	a.swap(b);
}

#if defined(_STLP_DONT_SUPPORT_REBIND_MEMBER_TEMPLATE) || (defined(_STLPORT_VERSION) && !defined(_STLP_MEMBER_TEMPLATE_CLASSES))
// working for STLport 5.1.3 and MSVC 6 SP5
template <class _Tp1, class _Tp2>
inline CryptoPP::AllocatorWithCleanup<_Tp2>&
__stl_alloc_rebind(CryptoPP::AllocatorWithCleanup<_Tp1>& __a, const _Tp2*)
{
	return (CryptoPP::AllocatorWithCleanup<_Tp2>&)(__a);
}
#endif

NAMESPACE_END

#if GCC_DIAGNOSTIC_AWARE
#  pragma GCC diagnostic pop
#endif

#endif
