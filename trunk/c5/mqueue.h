#ifndef CRYPTOPP_MQUEUE_H
#define CRYPTOPP_MQUEUE_H

#include "queue.h"
#include "filters.h"
#include <deque>

NAMESPACE_BEGIN(CryptoPP)

//! Message Queue
class CRYPTOPP_DLL MessageQueue : public AutoSignaling<BufferedTransformation>
{
public:
	MessageQueue(unsigned int nodeSize=256);

	void IsolatedInitialize(const NameValuePairs &parameters)
		{m_queue.IsolatedInitialize(parameters); m_lengths.assign(1, 0U); m_messageCounts.assign(1, 0U);}
	unsigned int Put2(const byte *begin, unsigned int length, int messageEnd, bool blocking)
	{
		m_queue.Put(begin, length);
		m_lengths.back() += length;
		if (messageEnd)
		{
			m_lengths.push_back(0);
			m_messageCounts.back()++;
		}
		return 0;
	}
	bool IsolatedFlush(bool hardFlush, bool blocking) {return false;}
	bool IsolatedMessageSeriesEnd(bool blocking)
		{m_messageCounts.push_back(0); return false;}

	unsigned long MaxRetrievable() const
		{return m_lengths.front();}
	bool AnyRetrievable() const
		{return m_lengths.front() > 0;}

	unsigned int TransferTo2(BufferedTransformation &target, unsigned long &transferBytes, const std::string &channel=NULL_CHANNEL, bool blocking=true);
	unsigned int CopyRangeTo2(BufferedTransformation &target, unsigned long &begin, unsigned long end=ULONG_MAX, const std::string &channel=NULL_CHANNEL, bool blocking=true) const;

	unsigned long TotalBytesRetrievable() const
		{return m_queue.MaxRetrievable();}
	unsigned int NumberOfMessages() const
		{return m_lengths.size()-1;}
	bool GetNextMessage();

	unsigned int NumberOfMessagesInThisSeries() const
		{return m_messageCounts[0];}
	unsigned int NumberOfMessageSeries() const
		{return m_messageCounts.size()-1;}

	unsigned int CopyMessagesTo(BufferedTransformation &target, unsigned int count=UINT_MAX, const std::string &channel=NULL_CHANNEL) const;

	const byte * Spy(unsigned int &contiguousSize) const;

	void swap(MessageQueue &rhs);

private:
	ByteQueue m_queue;
	std::deque<unsigned long> m_lengths, m_messageCounts;
};


//! A filter that checks messages on two channels for equality
class CRYPTOPP_DLL EqualityComparisonFilter : public Unflushable<Multichannel<Filter> >
{
public:
	struct MismatchDetected : public Exception {MismatchDetected() : Exception(DATA_INTEGRITY_CHECK_FAILED, "EqualityComparisonFilter: did not receive the same data on two channels") {}};

	/*! if throwIfNotEqual is false, this filter will output a '\0' byte when it detects a mismatch, '\1' otherwise */
	EqualityComparisonFilter(BufferedTransformation *attachment=NULL, bool throwIfNotEqual=true, const std::string &firstChannel="0", const std::string &secondChannel="1")
		: m_throwIfNotEqual(throwIfNotEqual), m_mismatchDetected(false)
		, m_firstChannel(firstChannel), m_secondChannel(secondChannel)
		{Detach(attachment);}

	unsigned int ChannelPut2(const std::string &channel, const byte *begin, unsigned int length, int messageEnd, bool blocking);
	bool ChannelMessageSeriesEnd(const std::string &channel, int propagation=-1, bool blocking=true);

private:
	unsigned int MapChannel(const std::string &channel) const;
	bool HandleMismatchDetected(bool blocking);

	bool m_throwIfNotEqual, m_mismatchDetected;
	std::string m_firstChannel, m_secondChannel;
	MessageQueue m_q[2];
};

NAMESPACE_END

NAMESPACE_BEGIN(std)
template<> inline void swap(CryptoPP::MessageQueue &a, CryptoPP::MessageQueue &b)
{
	a.swap(b);
}
NAMESPACE_END

#endif
