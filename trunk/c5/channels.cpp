// channels.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"
#include "channels.h"

NAMESPACE_BEGIN(CryptoPP)
USING_NAMESPACE(std)

#if 0
void MessageSwitch::AddDefaultRoute(BufferedTransformation &destination, const std::string &channel)
{
	m_defaultRoutes.push_back(Route(&destination, channel));
}

void MessageSwitch::AddRoute(unsigned int begin, unsigned int end, BufferedTransformation &destination, const std::string &channel)
{
	RangeRoute route(begin, end, Route(&destination, channel));
	RouteList::iterator it = upper_bound(m_routes.begin(), m_routes.end(), route);
	m_routes.insert(it, route);
}

/*
class MessageRouteIterator
{
public:
	typedef MessageSwitch::RouteList::const_iterator RouteIterator;
	typedef MessageSwitch::DefaultRouteList::const_iterator DefaultIterator;

	bool m_useDefault;
	RouteIterator m_itRouteCurrent, m_itRouteEnd;
	DefaultIterator m_itDefaultCurrent, m_itDefaultEnd;

	MessageRouteIterator(MessageSwitch &ms, const std::string &channel)
		: m_channel(channel)
	{
		pair<MapIterator, MapIterator> range = cs.m_routeMap.equal_range(channel);
		if (range.first == range.second)
		{
			m_useDefault = true;
			m_itListCurrent = cs.m_defaultRoutes.begin();
			m_itListEnd = cs.m_defaultRoutes.end();
		}
		else
		{
			m_useDefault = false;
			m_itMapCurrent = range.first;
			m_itMapEnd = range.second;
		}
	}

	bool End() const
	{
		return m_useDefault ? m_itListCurrent == m_itListEnd : m_itMapCurrent == m_itMapEnd;
	}

	void Next()
	{
		if (m_useDefault)
			++m_itListCurrent;
		else
			++m_itMapCurrent;
	}

	BufferedTransformation & Destination()
	{
		return m_useDefault ? *m_itListCurrent->first : *m_itMapCurrent->second.first;
	}

	const std::string & Message()
	{
		if (m_useDefault)
			return m_itListCurrent->second.get() ? *m_itListCurrent->second.get() : m_channel;
		else
			return m_itMapCurrent->second.second;
	}
};

void MessageSwitch::Put(byte inByte);
void MessageSwitch::Put(const byte *inString, unsigned int length);

void MessageSwitch::Flush(bool completeFlush, int propagation=-1);
void MessageSwitch::MessageEnd(int propagation=-1);
void MessageSwitch::PutMessageEnd(const byte *inString, unsigned int length, int propagation=-1);
void MessageSwitch::MessageSeriesEnd(int propagation=-1);
*/
#endif

class ChannelRouteIterator
{
public:
	typedef ChannelSwitch::RouteMap::const_iterator MapIterator;
	typedef ChannelSwitch::DefaultRouteList::const_iterator ListIterator;

	const std::string m_channel;
	bool m_useDefault;
	MapIterator m_itMapCurrent, m_itMapEnd;
	ListIterator m_itListCurrent, m_itListEnd;

	ChannelRouteIterator(ChannelSwitch &cs, const std::string &channel)
		: m_channel(channel)
	{
		pair<MapIterator, MapIterator> range = cs.m_routeMap.equal_range(channel);
		if (range.first == range.second)
		{
			m_useDefault = true;
			m_itListCurrent = cs.m_defaultRoutes.begin();
			m_itListEnd = cs.m_defaultRoutes.end();
		}
		else
		{
			m_useDefault = false;
			m_itMapCurrent = range.first;
			m_itMapEnd = range.second;
		}
	}

	bool End() const
	{
		return m_useDefault ? m_itListCurrent == m_itListEnd : m_itMapCurrent == m_itMapEnd;
	}

	void Next()
	{
		if (m_useDefault)
			++m_itListCurrent;
		else
			++m_itMapCurrent;
	}

	BufferedTransformation & Destination()
	{
		return m_useDefault ? *m_itListCurrent->first : *m_itMapCurrent->second.first;
	}

	const std::string & Channel()
	{
		if (m_useDefault)
			return m_itListCurrent->second.get() ? *m_itListCurrent->second.get() : m_channel;
		else
			return m_itMapCurrent->second.second;
	}
};

unsigned int ChannelSwitch::ChannelPut2(const std::string &channel, const byte *begin, unsigned int length, int messageEnd, bool blocking)
{
	if (!blocking)
		throw BlockingInputOnly("ChannelSwitch");

	ChannelRouteIterator it(*this, channel);
	while (!it.End())
	{
		it.Destination().ChannelPut2(it.Channel(), begin, length, messageEnd, blocking);
		it.Next();
	}
	return 0;
}

void ChannelSwitch::ChannelInitialize(const std::string &channel, const NameValuePairs &parameters/* =g_nullNameValuePairs */, int propagation/* =-1 */)
{
	if (channel.empty())
	{
		m_routeMap.clear();
		m_defaultRoutes.clear();
	}

	ChannelRouteIterator it(*this, channel);
	while (!it.End())
	{
		it.Destination().ChannelInitialize(it.Channel(), parameters, propagation);
		it.Next();
	}
}

bool ChannelSwitch::ChannelFlush(const std::string &channel, bool completeFlush, int propagation, bool blocking)
{
	if (!blocking)
		throw BlockingInputOnly("ChannelSwitch");

	ChannelRouteIterator it(*this, channel);
	while (!it.End())
	{
		it.Destination().ChannelFlush(it.Channel(), completeFlush, propagation, blocking);
		it.Next();
	}
	return false;
}

bool ChannelSwitch::ChannelMessageSeriesEnd(const std::string &channel, int propagation, bool blocking)
{
	if (!blocking)
		throw BlockingInputOnly("ChannelSwitch");

	ChannelRouteIterator it(*this, channel);
	while (!it.End())
	{
		it.Destination().ChannelMessageSeriesEnd(it.Channel(), propagation);
		it.Next();
	}
	return false;
}

byte * ChannelSwitch::ChannelCreatePutSpace(const std::string &channel, unsigned int &size)
{
	ChannelRouteIterator it(*this, channel);
	if (!it.End())
	{
		BufferedTransformation &target = it.Destination();
		it.Next();
		if (it.End())	// there is only one target channel
			return target.ChannelCreatePutSpace(it.Channel(), size);
	}
	size = 0;
	return NULL;
}

unsigned int ChannelSwitch::ChannelPutModifiable2(const std::string &channel, byte *inString, unsigned int length, int messageEnd, bool blocking)
{
	if (!blocking)
		throw BlockingInputOnly("ChannelSwitch");

	ChannelRouteIterator it(*this, channel);
	if (!it.End())
	{
		BufferedTransformation &target = it.Destination();
		const std::string &targetChannel = it.Channel();
		it.Next();
		if (it.End())	// there is only one target channel
			return target.ChannelPutModifiable2(targetChannel, inString, length, messageEnd, blocking);
	}
	ChannelPut2(channel, inString, length, messageEnd, blocking);
	return false;
}

void ChannelSwitch::AddDefaultRoute(BufferedTransformation &destination)
{
	m_defaultRoutes.push_back(DefaultRoute(&destination, value_ptr<std::string>(NULL)));
}

void ChannelSwitch::RemoveDefaultRoute(BufferedTransformation &destination)
{
	for (DefaultRouteList::iterator it = m_defaultRoutes.begin(); it != m_defaultRoutes.end(); ++it)
		if (it->first == &destination && !it->second.get())
		{
			m_defaultRoutes.erase(it);
			break;
		}
}

void ChannelSwitch::AddDefaultRoute(BufferedTransformation &destination, const std::string &outChannel)
{
	m_defaultRoutes.push_back(DefaultRoute(&destination, outChannel));
}

void ChannelSwitch::RemoveDefaultRoute(BufferedTransformation &destination, const std::string &outChannel)
{
	for (DefaultRouteList::iterator it = m_defaultRoutes.begin(); it != m_defaultRoutes.end(); ++it)
		if (it->first == &destination && (it->second.get() && *it->second == outChannel))
		{
			m_defaultRoutes.erase(it);
			break;
		}
}

void ChannelSwitch::AddRoute(const std::string &inChannel, BufferedTransformation &destination, const std::string &outChannel)
{
	m_routeMap.insert(RouteMap::value_type(inChannel, Route(&destination, outChannel)));
}

void ChannelSwitch::RemoveRoute(const std::string &inChannel, BufferedTransformation &destination, const std::string &outChannel)
{
	typedef ChannelSwitch::RouteMap::iterator MapIterator;
	pair<MapIterator, MapIterator> range = m_routeMap.equal_range(inChannel);
	
	for (MapIterator it = range.first; it != range.second; ++it)
		if (it->second.first == &destination && it->second.second == outChannel)
		{
			m_routeMap.erase(it);
			break;
		}
}

NAMESPACE_END
