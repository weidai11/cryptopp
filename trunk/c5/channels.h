#ifndef CRYPTOPP_CHANNELS_H
#define CRYPTOPP_CHANNELS_H

#include "simple.h"
#include "smartptr.h"
#include <map>
#include <list>

NAMESPACE_BEGIN(CryptoPP)

#if 0
//! Route input on default channel to different and/or multiple channels based on message sequence number
class MessageSwitch : public Sink
{
public:
	void AddDefaultRoute(BufferedTransformation &destination, const std::string &channel);
	void AddRoute(unsigned int begin, unsigned int end, BufferedTransformation &destination, const std::string &channel);

	void Put(byte inByte);
	void Put(const byte *inString, unsigned int length);

	void Flush(bool completeFlush, int propagation=-1);
	void MessageEnd(int propagation=-1);
	void PutMessageEnd(const byte *inString, unsigned int length, int propagation=-1);
	void MessageSeriesEnd(int propagation=-1);

private:
	typedef std::pair<BufferedTransformation *, std::string> Route;
	struct RangeRoute
	{
		RangeRoute(unsigned int begin, unsigned int end, const Route &route)
			: begin(begin), end(end), route(route) {}
		bool operator<(const RangeRoute &rhs) const {return begin < rhs.begin;}
		unsigned int begin, end;
		Route route;
	};

	typedef std::list<RangeRoute> RouteList;
	typedef std::list<Route> DefaultRouteList;

	RouteList m_routes;
	DefaultRouteList m_defaultRoutes;
	unsigned int m_nCurrentMessage;
};
#endif

//! Route input to different and/or multiple channels based on channel ID
class ChannelSwitch : public Multichannel<Sink>
{
public:
	ChannelSwitch() {}
	ChannelSwitch(BufferedTransformation &destination)
	{
		AddDefaultRoute(destination);
	}
	ChannelSwitch(BufferedTransformation &destination, const std::string &outChannel)
	{
		AddDefaultRoute(destination, outChannel);
	}

	unsigned int ChannelPut2(const std::string &channel, const byte *begin, unsigned int length, int messageEnd, bool blocking);
	unsigned int ChannelPutModifiable2(const std::string &channel, byte *begin, unsigned int length, int messageEnd, bool blocking);

	void ChannelInitialize(const std::string &channel, const NameValuePairs &parameters=g_nullNameValuePairs, int propagation=-1);
	bool ChannelFlush(const std::string &channel, bool completeFlush, int propagation=-1, bool blocking=true);
	bool ChannelMessageSeriesEnd(const std::string &channel, int propagation=-1, bool blocking=true);

	byte * ChannelCreatePutSpace(const std::string &channel, unsigned int &size);
	
	void AddDefaultRoute(BufferedTransformation &destination);
	void RemoveDefaultRoute(BufferedTransformation &destination);
	void AddDefaultRoute(BufferedTransformation &destination, const std::string &outChannel);
	void RemoveDefaultRoute(BufferedTransformation &destination, const std::string &outChannel);
	void AddRoute(const std::string &inChannel, BufferedTransformation &destination, const std::string &outChannel);
	void RemoveRoute(const std::string &inChannel, BufferedTransformation &destination, const std::string &outChannel);

private:
	typedef std::pair<BufferedTransformation *, std::string> Route;
	typedef std::multimap<std::string, Route> RouteMap;
	RouteMap m_routeMap;

	typedef std::pair<BufferedTransformation *, value_ptr<std::string> > DefaultRoute;
	typedef std::list<DefaultRoute> DefaultRouteList;
	DefaultRouteList m_defaultRoutes;

	friend class ChannelRouteIterator;
};

NAMESPACE_END

#endif
