// secblock.h - written and placed in the public domain by Wei Dai

#ifndef CRYPTOPP_SECBLOCK_H
#define CRYPTOPP_SECBLOCK_H

#include "config.h"
#include "misc.h"
#include <string.h>		// CodeWarrior doesn't have memory.h
#include <assert.h>

NAMESPACE_BEGIN(CryptoPP)

// ************** secure memory allocation ***************

template<class T>
class AllocatorBase
{
public:
	typedef T value_type;
	typedef size_t size_type;
#if (defined(_MSC_VER) && _MSC_VER < 1300)
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
	size_type max_size() const {return size_type(-1)/sizeof(T);}
};

#define CRYPTOPP_INHERIT_ALLOCATOR_TYPES	\
typedef typename AllocatorBase<T>::value_type value_type;\
typedef typename AllocatorBase<T>::size_type size_type;\
typedef typename AllocatorBase<T>::difference_type difference_type;\
typedef typename AllocatorBase<T>::pointer pointer;\
typedef typename AllocatorBase<T>::const_pointer const_pointer;\
typedef typename AllocatorBase<T>::reference reference;\
typedef typename AllocatorBase<T>::const_reference const_reference;

template <class T, class A>
typename A::pointer StandardReallocate(A& a, T *p, typename A::size_type oldSize, typename A::size_type newSize, bool preserve)
{
	if (oldSize == newSize)
		return p;

	if (preserve)
	{
		typename A::pointer newPointer = a.allocate(newSize, NULL);
		memcpy(newPointer, p, sizeof(T)*STDMIN(oldSize, newSize));
		a.deallocate(p, oldSize);
		return newPointer;
	}
	else
	{
		a.deallocate(p, oldSize);
		return a.allocate(newSize, NULL);
	}
}

template <class T>
class AllocatorWithCleanup : public AllocatorBase<T>
{
public:
	CRYPTOPP_INHERIT_ALLOCATOR_TYPES

	pointer allocate(size_type n, const void * = NULL)
	{
		if (n > 0)
			return new T[n];
		else
			return NULL;
	}

	void deallocate(void *p, size_type n)
	{
		memset(p, 0, n*sizeof(T));
		delete [] (T *)p;
	}

	pointer reallocate(T *p, size_type oldSize, size_type newSize, bool preserve)
	{
		return StandardReallocate(*this, p, oldSize, newSize, preserve);
	}

	// VS.NET STL enforces the policy of "All STL-compliant allocators have to provide a
	// template class member called rebind".
    template <class U> struct rebind { typedef AllocatorWithCleanup<U> other; };
};

template <class T>
class NullAllocator : public AllocatorBase<T>
{
public:
	CRYPTOPP_INHERIT_ALLOCATOR_TYPES

	pointer allocate(size_type n, const void * = NULL)
	{
		assert(false);
		return NULL;
	}

	void deallocate(void *p, size_type n)
	{
		assert(false);
	}
};

// this allocator can't be used with standard collections
template <class T, unsigned int S, class A = NullAllocator<T> >
class FixedSizeAllocatorWithCleanup : public AllocatorBase<T>
{
public:
	CRYPTOPP_INHERIT_ALLOCATOR_TYPES

	pointer allocate(size_type n)
	{
		if (n <= S)
		{
			assert(!m_allocated);
#ifndef NDEBUG
			m_allocated = true;
#endif
			return m_array;
		}
		else
			return m_fallbackAllocator.allocate(n);
	}

	pointer allocate(size_type n, const void *hint)
	{
		if (n <= S)
		{
			assert(!m_allocated);
#ifndef NDEBUG
			m_allocated = true;
#endif
			return m_array;
		}
		else
			return m_fallbackAllocator.allocate(n, hint);
	}

	void deallocate(void *p, size_type n)
	{
		if (n <= S)
		{
			assert(m_allocated);
			assert(p == m_array);
#ifndef NDEBUG
			m_allocated = false;
#endif
			memset(p, 0, n*sizeof(T));
		}
		else
			m_fallbackAllocator.deallocate(p, n);
	}

	pointer reallocate(pointer p, size_type oldSize, size_type newSize, bool preserve)
	{
		if (oldSize <= S && newSize <= S)
			return p;

		return StandardReallocate(*this, p, oldSize, newSize, preserve);
	}

	size_type max_size() const {return m_fallbackAllocator.max_size();}

private:
	A m_fallbackAllocator;
	T m_array[S];

#ifndef NDEBUG
public:
	FixedSizeAllocatorWithCleanup() : m_allocated(false) {}
	bool m_allocated;
#endif
};

//! a block of memory allocated using A
template <class T, class A = AllocatorWithCleanup<T> >
class SecBlock
{
public:
	explicit SecBlock(unsigned int size=0)
		: m_size(size) {m_ptr = m_alloc.allocate(size, NULL);}
	SecBlock(const SecBlock<T, A> &t)
		: m_size(t.m_size) {m_ptr = m_alloc.allocate(m_size, NULL); memcpy(m_ptr, t.m_ptr, m_size*sizeof(T));}
	SecBlock(const T *t, unsigned int len)
		: m_size(len)
	{
		m_ptr = m_alloc.allocate(len, NULL);
		if (t == NULL)
			memset(m_ptr, 0, len*sizeof(T));
		else
			memcpy(m_ptr, t, len*sizeof(T));
	}

	~SecBlock()
		{m_alloc.deallocate(m_ptr, m_size);}

#if defined(__GNUC__) || defined(__BCPLUSPLUS__)
	operator const void *() const
		{return m_ptr;}
	operator void *()
		{return m_ptr;}
#endif
#if defined(__GNUC__)	// reduce warnings
	operator const void *()
		{return m_ptr;}
#endif

	operator const T *() const
		{return m_ptr;}
	operator T *()
		{return m_ptr;}
#if defined(__GNUC__)	// reduce warnings
	operator const T *()
		{return m_ptr;}
#endif

	template <typename I>
	T *operator +(I offset)
		{return m_ptr+offset;}

	template <typename I>
	const T *operator +(I offset) const
		{return m_ptr+offset;}

	template <typename I>
	T& operator[](I index)
		{assert(index >= 0 && (unsigned int)index < m_size); return m_ptr[index];}

	template <typename I>
	const T& operator[](I index) const
		{assert(index >= 0 && (unsigned int)index < m_size); return m_ptr[index];}

	typedef typename A::pointer iterator;
	typedef typename A::const_pointer const_iterator;
	typedef typename A::size_type size_type;

	iterator begin()
		{return m_ptr;}
	const_iterator begin() const
		{return m_ptr;}
	iterator end()
		{return m_ptr+m_size;}
	const_iterator end() const
		{return m_ptr+m_size;}

	typename A::pointer data() {return m_ptr;}
	typename A::const_pointer data() const {return m_ptr;}

	size_type size() const {return m_size;}
	bool empty() const {return m_size == 0;}

	void Assign(const T *t, unsigned int len)
	{
		New(len);
		memcpy(m_ptr, t, len*sizeof(T));
	}

	void Assign(const SecBlock<T, A> &t)
	{
		New(t.m_size);
		memcpy(m_ptr, t.m_ptr, m_size*sizeof(T));
	}

	SecBlock& operator=(const SecBlock<T, A> &t)
	{
		Assign(t);
		return *this;
	}

	bool operator==(const SecBlock<T, A> &t) const
	{
		return m_size == t.m_size && memcmp(m_ptr, t.m_ptr, m_size*sizeof(T)) == 0;
	}

	bool operator!=(const SecBlock<T, A> &t) const
	{
		return !operator==(t);
	}

	void New(unsigned int newSize)
	{
		m_ptr = m_alloc.reallocate(m_ptr, m_size, newSize, false);
		m_size = newSize;
	}

	void CleanNew(unsigned int newSize)
	{
		New(newSize);
		memset(m_ptr, 0, m_size*sizeof(T));
	}

	void Grow(unsigned int newSize)
	{
		if (newSize > m_size)
		{
			m_ptr = m_alloc.reallocate(m_ptr, m_size, newSize, true);
			m_size = newSize;
		}
	}

	void CleanGrow(unsigned int newSize)
	{
		if (newSize > m_size)
		{
			m_ptr = m_alloc.reallocate(m_ptr, m_size, newSize, true);
			memset(m_ptr+m_size, 0, (newSize-m_size)*sizeof(T));
			m_size = newSize;
		}
	}

	void resize(unsigned int newSize)
	{
		m_ptr = m_alloc.reallocate(m_ptr, m_size, newSize, true);
		m_size = newSize;
	}

	void swap(SecBlock<T, A> &b);

//private:
	A m_alloc;
	unsigned int m_size;
	T *m_ptr;
};

template <class T, class A> void SecBlock<T, A>::swap(SecBlock<T, A> &b)
{
	std::swap(m_alloc, b.m_alloc);
	std::swap(m_size, b.m_size);
	std::swap(m_ptr, b.m_ptr);
}

typedef SecBlock<byte> SecByteBlock;
typedef SecBlock<word> SecWordBlock;

template <class T, unsigned int S, class A = FixedSizeAllocatorWithCleanup<T, S> >
class FixedSizeSecBlock : public SecBlock<T, A>
{
public:
	explicit FixedSizeSecBlock() : SecBlock<T, A>(S) {}
};

template <class T, unsigned int S, class A = FixedSizeAllocatorWithCleanup<T, S, AllocatorWithCleanup<T> > >
class SecBlockWithHint : public SecBlock<T, A>
{
public:
	explicit SecBlockWithHint(unsigned int size) : SecBlock<T, A>(size) {}
};

template<class T, class U>
inline bool operator==(const CryptoPP::AllocatorWithCleanup<T>&, const CryptoPP::AllocatorWithCleanup<U>&) {return (true);}
template<class T, class U>
inline bool operator!=(const CryptoPP::AllocatorWithCleanup<T>&, const CryptoPP::AllocatorWithCleanup<U>&) {return (false);}

NAMESPACE_END

NAMESPACE_BEGIN(std)
template <class T, class A>
inline void swap(CryptoPP::SecBlock<T, A> &a, CryptoPP::SecBlock<T, A> &b)
{
	a.swap(b);
}

#if defined(_STLPORT_VERSION) && !defined(_STLP_MEMBER_TEMPLATE_CLASSES)
template <class _Tp1, class _Tp2>
inline CryptoPP::AllocatorWithCleanup<_Tp2>&
__stl_alloc_rebind(CryptoPP::AllocatorWithCleanup<_Tp1>& __a, const _Tp2*)
{
	return (CryptoPP::AllocatorWithCleanup<_Tp2>&)(__a);
}
#endif

NAMESPACE_END

#endif
