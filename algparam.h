#ifndef CRYPTOPP_ALGPARAM_H
#define CRYPTOPP_ALGPARAM_H

#include "cryptlib.h"
#include "smartptr.h"
#include "secblock.h"

NAMESPACE_BEGIN(CryptoPP)

//! used to pass byte array input as part of a NameValuePairs object
/*! the deepCopy option is used when the NameValuePairs object can't
	keep a copy of the data available */
class ConstByteArrayParameter
{
public:
	ConstByteArrayParameter(const char *data = NULL, bool deepCopy = false)
	{
		Assign((const byte *)data, data ? strlen(data) : 0, deepCopy);
	}
	ConstByteArrayParameter(const byte *data, unsigned int size, bool deepCopy = false)
	{
		Assign(data, size, deepCopy);
	}
	template <class T> ConstByteArrayParameter(const T &string, bool deepCopy = false)
	{
		CRYPTOPP_COMPILE_ASSERT(sizeof(string[0])==1);
		Assign((const byte *)string.data(), string.size(), deepCopy);
	}

	void Assign(const byte *data, unsigned int size, bool deepCopy)
	{
		if (deepCopy)
			m_block.Assign(data, size);
		else
		{
			m_data = data;
			m_size = size;
		}
		m_deepCopy = deepCopy;
	}

	const byte *begin() const {return m_deepCopy ? m_block.begin() : m_data;}
	const byte *end() const {return m_deepCopy ? m_block.end() : m_data + m_size;}
	unsigned int size() const {return m_deepCopy ? m_block.size() : m_size;}

private:
	bool m_deepCopy;
	const byte *m_data;
	unsigned int m_size;
	SecByteBlock m_block;
};

class ByteArrayParameter
{
public:
	ByteArrayParameter(byte *data = NULL, unsigned int size = 0)
		: m_data(data), m_size(size) {}
	ByteArrayParameter(SecByteBlock &block)
		: m_data(block.begin()), m_size(block.size()) {}

	byte *begin() const {return m_data;}
	byte *end() const {return m_data + m_size;}
	unsigned int size() const {return m_size;}

private:
	byte *m_data;
	unsigned int m_size;
};

class CombinedNameValuePairs : public NameValuePairs
{
public:
	CombinedNameValuePairs(const NameValuePairs &pairs1, const NameValuePairs &pairs2)
		: m_pairs1(pairs1), m_pairs2(pairs2) {}

	bool GetVoidValue(const char *name, const std::type_info &valueType, void *pValue) const
	{
		if (strcmp(name, "ValueNames") == 0)
			return m_pairs1.GetVoidValue(name, valueType, pValue) && m_pairs2.GetVoidValue(name, valueType, pValue);
		else
			return m_pairs1.GetVoidValue(name, valueType, pValue) || m_pairs2.GetVoidValue(name, valueType, pValue);
	}

	const NameValuePairs &m_pairs1, &m_pairs2;
};

template <class T, class BASE>
class GetValueHelperClass
{
public:
	GetValueHelperClass(const T *pObject, const char *name, const std::type_info &valueType, void *pValue, const NameValuePairs *searchFirst)
		: m_pObject(pObject), m_name(name), m_valueType(&valueType), m_pValue(pValue), m_found(false), m_getValueNames(false)
	{
		if (strcmp(m_name, "ValueNames") == 0)
		{
			m_found = m_getValueNames = true;
			NameValuePairs::ThrowIfTypeMismatch(m_name, typeid(std::string), *m_valueType);
			if (searchFirst)
				searchFirst->GetVoidValue(m_name, valueType, pValue);
			if (typeid(T) != typeid(BASE))
				pObject->BASE::GetVoidValue(m_name, valueType, pValue);
			((*reinterpret_cast<std::string *>(m_pValue) += "ThisPointer:") += typeid(T).name()) += ';';
		}

		if (!m_found && strncmp(m_name, "ThisPointer:", 12) == 0 && strcmp(m_name+12, typeid(T).name()) == 0)
		{
			NameValuePairs::ThrowIfTypeMismatch(m_name, typeid(T *), *m_valueType);
			*reinterpret_cast<const T **>(pValue) = pObject;
			m_found = true;
			return;
		}

		if (!m_found && searchFirst)
			m_found = searchFirst->GetVoidValue(m_name, valueType, pValue);
		
		if (!m_found && typeid(T) != typeid(BASE))
			m_found = pObject->BASE::GetVoidValue(m_name, valueType, pValue);
	}

	operator bool() const {return m_found;}

	template <class R>
	GetValueHelperClass<T,BASE> & operator()(const char *name, const R & (T::*pm)() const)
	{
		if (m_getValueNames)
			(*reinterpret_cast<std::string *>(m_pValue) += name) += ";";
		if (!m_found && strcmp(name, m_name) == 0)
		{
			NameValuePairs::ThrowIfTypeMismatch(name, typeid(R), *m_valueType);
			*reinterpret_cast<R *>(m_pValue) = (m_pObject->*pm)();
			m_found = true;
		}
		return *this;
	}

	GetValueHelperClass<T,BASE> &Assignable()
	{
		if (m_getValueNames)
			((*reinterpret_cast<std::string *>(m_pValue) += "ThisObject:") += typeid(T).name()) += ';';
		if (!m_found && strncmp(m_name, "ThisObject:", 11) == 0 && strcmp(m_name+11, typeid(T).name()) == 0)
		{
			NameValuePairs::ThrowIfTypeMismatch(m_name, typeid(T), *m_valueType);
			*reinterpret_cast<T *>(m_pValue) = *m_pObject;
			m_found = true;
		}
		return *this;
	}

private:
	const T *m_pObject;
	const char *m_name;
	const std::type_info *m_valueType;
	void *m_pValue;
	bool m_found, m_getValueNames;
};

template <class BASE, class T>
GetValueHelperClass<T, BASE> GetValueHelper(const T *pObject, const char *name, const std::type_info &valueType, void *pValue, const NameValuePairs *searchFirst=NULL, BASE *dummy=NULL)
{
	return GetValueHelperClass<T, BASE>(pObject, name, valueType, pValue, searchFirst);
}

template <class T>
GetValueHelperClass<T, T> GetValueHelper(const T *pObject, const char *name, const std::type_info &valueType, void *pValue, const NameValuePairs *searchFirst=NULL)
{
	return GetValueHelperClass<T, T>(pObject, name, valueType, pValue, searchFirst);
}

// ********************************************************

template <class R>
R Hack_DefaultValueFromConstReferenceType(const R &)
{
	return R();
}

template <class R>
bool Hack_GetValueIntoConstReference(const NameValuePairs &source, const char *name, const R &value)
{
	return source.GetValue(name, const_cast<R &>(value));
}

template <class T, class BASE>
class AssignFromHelperClass
{
public:
	AssignFromHelperClass(T *pObject, const NameValuePairs &source)
		: m_pObject(pObject), m_source(source), m_done(false)
	{
		if (source.GetThisObject(*pObject))
			m_done = true;
		else if (typeid(BASE) != typeid(T))
			pObject->BASE::AssignFrom(source);
	}

	template <class R>
	AssignFromHelperClass & operator()(const char *name, void (T::*pm)(R))	// VC60 workaround: "const R &" here causes compiler error
	{
		if (!m_done)
		{
			R value = Hack_DefaultValueFromConstReferenceType(reinterpret_cast<R>(*(int *)NULL));
			if (!Hack_GetValueIntoConstReference(m_source, name, value))
				throw InvalidArgument(std::string(typeid(T).name()) + ": Missing required parameter '" + name + "'");
			(m_pObject->*pm)(value);
		}
		return *this;
	}

	template <class R, class S>
	AssignFromHelperClass & operator()(const char *name1, const char *name2, void (T::*pm)(R, S))	// VC60 workaround: "const R &" here causes compiler error
	{
		if (!m_done)
		{
			R value1 = Hack_DefaultValueFromConstReferenceType(reinterpret_cast<R>(*(int *)NULL));
			if (!Hack_GetValueIntoConstReference(m_source, name1, value1))
				throw InvalidArgument(std::string(typeid(T).name()) + ": Missing required parameter '" + name1 + "'");
			S value2 = Hack_DefaultValueFromConstReferenceType(reinterpret_cast<S>(*(int *)NULL));
			if (!Hack_GetValueIntoConstReference(m_source, name2, value2))
				throw InvalidArgument(std::string(typeid(T).name()) + ": Missing required parameter '" + name2 + "'");
			(m_pObject->*pm)(value1, value2);
		}
		return *this;
	}

private:
	T *m_pObject;
	const NameValuePairs &m_source;
	bool m_done;
};

template <class BASE, class T>
AssignFromHelperClass<T, BASE> AssignFromHelper(T *pObject, const NameValuePairs &source, BASE *dummy=NULL)
{
	return AssignFromHelperClass<T, BASE>(pObject, source);
}

template <class T>
AssignFromHelperClass<T, T> AssignFromHelper(T *pObject, const NameValuePairs &source)
{
	return AssignFromHelperClass<T, T>(pObject, source);
}

// ********************************************************

// This should allow the linker to discard Integer code if not needed.
extern bool (*AssignIntToInteger)(const std::type_info &valueType, void *pInteger, const void *pInt);

const std::type_info & IntegerTypeId();

template <class BASE, class T>
class AlgorithmParameters : public NameValuePairs
{
public:
	AlgorithmParameters(const BASE &base, const char *name, const T &value)
		: m_base(base), m_name(name), m_value(value)
#ifndef NDEBUG
		, m_used(false)
#endif
	{}

#ifndef NDEBUG
	AlgorithmParameters(const AlgorithmParameters &copy)
		: m_base(copy.m_base), m_name(copy.m_name), m_value(copy.m_value), m_used(false)
	{
		copy.m_used = true;
	}

	// TODO: revisit after implementing some tracing mechanism, this won't work because of exceptions
//	~AlgorithmParameters() {assert(m_used);}	// use assert here because we don't want to throw out of a destructor
#endif

	template <class R>
	AlgorithmParameters<AlgorithmParameters<BASE,T>, R> operator()(const char *name, const R &value) const
	{
		return AlgorithmParameters<AlgorithmParameters<BASE,T>, R>(*this, name, value);
	}

	bool GetVoidValue(const char *name, const std::type_info &valueType, void *pValue) const
	{
		if (strcmp(name, "ValueNames") == 0)
		{
			ThrowIfTypeMismatch(name, typeid(std::string), valueType);
			m_base.GetVoidValue(name, valueType, pValue);
			(*reinterpret_cast<std::string *>(pValue) += m_name) += ";";
			return true;
		}
		else if (strcmp(name, m_name) == 0)
		{
			// special case for retrieving an Integer parameter when an int was passed in
			if (!(AssignIntToInteger != NULL && typeid(T) == typeid(int) && AssignIntToInteger(valueType, pValue, &m_value)))
			{
				ThrowIfTypeMismatch(name, typeid(T), valueType);
				*reinterpret_cast<T *>(pValue) = m_value;
			}
#ifndef NDEBUG
			m_used = true;
#endif
			return true;
		}
		else
			return m_base.GetVoidValue(name, valueType, pValue);
	}

private:
	BASE m_base;
	const char *m_name;
	T m_value;
#ifndef NDEBUG
	mutable bool m_used;
#endif
};

template <class T>
AlgorithmParameters<NullNameValuePairs,T> MakeParameters(const char *name, const T &value)
{
	return AlgorithmParameters<NullNameValuePairs,T>(g_nullNameValuePairs, name, value);
}

#define CRYPTOPP_GET_FUNCTION_ENTRY(name)		(Name::name(), &ThisClass::Get##name)
#define CRYPTOPP_SET_FUNCTION_ENTRY(name)		(Name::name(), &ThisClass::Set##name)
#define CRYPTOPP_SET_FUNCTION_ENTRY2(name1, name2)	(Name::name1(), Name::name2(), &ThisClass::Set##name1##And##name2)

NAMESPACE_END

#endif
