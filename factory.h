#ifndef CRYPTOPP_OBJFACT_H
#define CRYPTOPP_OBJFACT_H

#include "cryptlib.h"
#include <map>

NAMESPACE_BEGIN(CryptoPP)

template <class AbstractClass>
class ObjectFactory
{
public:
	virtual AbstractClass * CreateObject() const =0;
};

template <class AbstractClass, class ConcreteClass>
class DefaultObjectFactory : public ObjectFactory<AbstractClass>
{
public:
	AbstractClass * CreateObject() const
	{
		return new ConcreteClass;
	}
	
};

template <class AbstractClass, int instance=0>
class ObjectFactoryRegistry
{
public:
	~ObjectFactoryRegistry()
	{
		for (CPP_TYPENAME Map::iterator i = m_map.begin(); i != m_map.end(); ++i)
		{
			delete (ObjectFactory<AbstractClass> *)i->second;
			i->second = NULL;
		}
	}

	void RegisterFactory(const char *name, ObjectFactory<AbstractClass> *factory)
	{
		m_map[name] = factory;
	}

	const ObjectFactory<AbstractClass> * GetFactory(const char *name) const
	{
		CPP_TYPENAME Map::const_iterator i = m_map.find(name);
		return i == m_map.end() ? NULL : (ObjectFactory<AbstractClass> *)i->second;
	}

	AbstractClass *CreateObject(const char *name) const
	{
		const ObjectFactory<AbstractClass> *factory = GetFactory(name);
		return factory ? factory->CreateObject() : NULL;
	}

	// VC60 workaround: use "..." to prevent this function from being inlined
	static ObjectFactoryRegistry<AbstractClass, instance> & Registry(...);

private:
	// use void * instead of ObjectFactory<AbstractClass> * to save code size
	typedef std::map<std::string, void *> Map;
	Map m_map;
};

template <class AbstractClass, int instance>
ObjectFactoryRegistry<AbstractClass, instance> & ObjectFactoryRegistry<AbstractClass, instance>::Registry(...)
{
	static ObjectFactoryRegistry<AbstractClass, instance> s_registry;
	return s_registry;
}

template <class AbstractClass, class ConcreteClass, int instance = 0>
struct RegisterDefaultFactoryFor {
RegisterDefaultFactoryFor(const char *name)
{
	ObjectFactoryRegistry<AbstractClass, instance>::Registry().RegisterFactory(name, new DefaultObjectFactory<AbstractClass, ConcreteClass>);
}};

template <class SchemeClass>
void RegisterAsymmetricCipherDefaultFactories(const char *name, SchemeClass *dummy=NULL)
{
	RegisterDefaultFactoryFor<PK_Encryptor, CPP_TYPENAME SchemeClass::Encryptor>((const char *)name);
	RegisterDefaultFactoryFor<PK_Decryptor, CPP_TYPENAME SchemeClass::Decryptor>((const char *)name);
}

template <class SchemeClass>
void RegisterSignatureSchemeDefaultFactories(const char *name, SchemeClass *dummy=NULL)
{
	RegisterDefaultFactoryFor<PK_Signer, CPP_TYPENAME SchemeClass::Signer>((const char *)name);
	RegisterDefaultFactoryFor<PK_Verifier, CPP_TYPENAME SchemeClass::Verifier>((const char *)name);
}

template <class SchemeClass>
void RegisterSymmetricCipherDefaultFactories(const char *name, SchemeClass *dummy=NULL)
{
	RegisterDefaultFactoryFor<SymmetricCipher, CPP_TYPENAME SchemeClass::Encryption, ENCRYPTION>((const char *)name);
	RegisterDefaultFactoryFor<SymmetricCipher, CPP_TYPENAME SchemeClass::Decryption, DECRYPTION>((const char *)name);
}

NAMESPACE_END

#endif
