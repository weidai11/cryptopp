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

template <class AbstractClass>
class ObjectFactoryRegistry
{
public:
	~ObjectFactoryRegistry()
	{
		for (CPP_TYPENAME Map::iterator i = m_map.begin(); i != m_map.end(); ++i)
		{
			delete i->second;
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
		return i == m_map.end() ? NULL : i->second;
	}

	AbstractClass *CreateObject(const char *name) const
	{
		const ObjectFactory<AbstractClass> *factory = GetFactory(name);
		return factory ? factory->CreateObject() : NULL;
	}

	// VC60 workaround: use "..." to prevent this function from being inlined
	static ObjectFactoryRegistry<AbstractClass> & Registry(...);

private:
	typedef std::map<std::string, ObjectFactory<AbstractClass> *> Map;
	Map m_map;
};

template <class AbstractClass>
ObjectFactoryRegistry<AbstractClass> & ObjectFactoryRegistry<AbstractClass>::Registry(...)
{
	static ObjectFactoryRegistry<AbstractClass> s_registry;
	return s_registry;
}

template <class AbstractClass, class ConcreteClass>
void RegisterDefaultFactoryFor(const char *name, AbstractClass *Dummy1=NULL, ConcreteClass *Dummy2=NULL)
{
	ObjectFactoryRegistry<AbstractClass>::Registry().RegisterFactory(name, new DefaultObjectFactory<AbstractClass, ConcreteClass>);
}

template <class SchemeClass>
void RegisterPublicKeyCryptoSystemDefaultFactories(const char *name, SchemeClass *dummy=NULL)
{
	RegisterDefaultFactoryFor<PK_Encryptor, CPP_TYPENAME SchemeClass::Encryptor>(name);
	RegisterDefaultFactoryFor<PK_Decryptor, CPP_TYPENAME SchemeClass::Decryptor>(name);
}

template <class SchemeClass>
void RegisterSignatureSchemeDefaultFactories(const char *name, SchemeClass *dummy=NULL)
{
	RegisterDefaultFactoryFor<PK_Signer, CPP_TYPENAME SchemeClass::Signer>(name);
	RegisterDefaultFactoryFor<PK_Verifier, CPP_TYPENAME SchemeClass::Verifier>(name);
}

NAMESPACE_END

#endif
