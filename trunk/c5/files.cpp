// files.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"

#ifndef CRYPTOPP_IMPORTS

#include "files.h"

NAMESPACE_BEGIN(CryptoPP)

using namespace std;

void Files_TestInstantiations()
{
	FileStore f0;
	FileSource f1;
	FileSink f2;
}

void FileStore::StoreInitialize(const NameValuePairs &parameters)
{
	m_file.reset(new std::ifstream);
	const char *fileName;
	if (parameters.GetValue(Name::InputFileName(), fileName))
	{
		ios::openmode binary = parameters.GetValueWithDefault(Name::InputBinaryMode(), true) ? ios::binary : ios::openmode(0);
		m_file->open(fileName, ios::in | binary);
		if (!*m_file)
			throw OpenErr(fileName);
		m_stream = m_file.get();
	}
	else
	{
		m_stream = NULL;
		parameters.GetValue(Name::InputStreamPointer(), m_stream);
	}
	m_waiting = false;
}

unsigned long FileStore::MaxRetrievable() const
{
	if (!m_stream)
		return 0;

	streampos current = m_stream->tellg();
	streampos end = m_stream->seekg(0, ios::end).tellg();
	m_stream->seekg(current);
	return end-current;
}

unsigned int FileStore::TransferTo2(BufferedTransformation &target, unsigned long &transferBytes, const std::string &channel, bool blocking)
{
	if (!m_stream)
	{
		transferBytes = 0;
		return 0;
	}

	unsigned long size=transferBytes;
	transferBytes = 0;

	if (m_waiting)
		goto output;

	while (size && m_stream->good())
	{
		{
		unsigned int spaceSize = 1024;
		m_space = HelpCreatePutSpace(target, channel, 1, (unsigned int)STDMIN(size, (unsigned long)UINT_MAX), spaceSize);

		m_stream->read((char *)m_space, STDMIN(size, (unsigned long)spaceSize));
		}
		m_len = m_stream->gcount();
		unsigned int blockedBytes;
output:
		blockedBytes = target.ChannelPutModifiable2(channel, m_space, m_len, 0, blocking);
		m_waiting = blockedBytes > 0;
		if (m_waiting)
			return blockedBytes;
		size -= m_len;
		transferBytes += m_len;
	}

	if (!m_stream->good() && !m_stream->eof())
		throw ReadErr();

	return 0;
}

unsigned int FileStore::CopyRangeTo2(BufferedTransformation &target, unsigned long &begin, unsigned long end, const std::string &channel, bool blocking) const
{
	if (!m_stream)
		return 0;

	if (begin == 0 && end == 1)
	{
		int result = m_stream->peek();
		if (result == EOF)	// GCC workaround: 2.95.2 doesn't have char_traits<char>::eof()
			return 0;
		else
		{
			unsigned int blockedBytes = target.ChannelPut(channel, byte(result), blocking);
			begin += 1-blockedBytes;
			return blockedBytes;
		}
	}

	// TODO: figure out what happens on cin
	streampos current = m_stream->tellg();
	streampos endPosition = m_stream->seekg(0, ios::end).tellg();
	streampos newPosition = current + (streamoff)begin;

	if (newPosition >= endPosition)
	{
		m_stream->seekg(current);
		return 0;	// don't try to seek beyond the end of file
	}
	m_stream->seekg(newPosition);
	unsigned long total = 0;
	try
	{
		assert(!m_waiting);
		unsigned long copyMax = end-begin;
		unsigned int blockedBytes = const_cast<FileStore *>(this)->TransferTo2(target, copyMax, channel, blocking);
		begin += copyMax;
		if (blockedBytes)
		{
			const_cast<FileStore *>(this)->m_waiting = false;
			return blockedBytes;
		}
	}
	catch(...)
	{
		m_stream->clear();
		m_stream->seekg(current);
		throw;
	}
	m_stream->clear();
	m_stream->seekg(current);

	return 0;
}

unsigned long FileStore::Skip(unsigned long skipMax)
{
	unsigned long oldPos = m_stream->tellg();
	m_stream->seekg(skipMax, ios::cur);
	return (unsigned long)m_stream->tellg() - oldPos;
}

void FileSink::IsolatedInitialize(const NameValuePairs &parameters)
{
	m_file.reset(new std::ofstream);
	const char *fileName;
	if (parameters.GetValue(Name::OutputFileName(), fileName))
	{
		ios::openmode binary = parameters.GetValueWithDefault(Name::OutputBinaryMode(), true) ? ios::binary : ios::openmode(0);
		m_file->open(fileName, ios::out | ios::trunc | binary);
		if (!*m_file)
			throw OpenErr(fileName);
		m_stream = m_file.get();
	}
	else
	{
		m_stream = NULL;
		parameters.GetValue(Name::OutputStreamPointer(), m_stream);
	}
}

bool FileSink::IsolatedFlush(bool hardFlush, bool blocking)
{
	if (!m_stream)
		throw Err("FileSink: output stream not opened");

	m_stream->flush();
	if (!m_stream->good())
		throw WriteErr();

	return false;
}

unsigned int FileSink::Put2(const byte *inString, unsigned int length, int messageEnd, bool blocking)
{
	if (!m_stream)
		throw Err("FileSink: output stream not opened");

	m_stream->write((const char *)inString, length);

	if (messageEnd)
		m_stream->flush();

	if (!m_stream->good())
		throw WriteErr();

	return 0;
}

NAMESPACE_END

#endif
