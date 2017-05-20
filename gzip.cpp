// gzip.cpp - originally written and placed in the public domain by Wei Dai

#include "pch.h"
#include "gzip.h"
#include "argnames.h"

NAMESPACE_BEGIN(CryptoPP)

// Checks whether the character is valid for ISO/IEC 8859-1 as required by RFC 1952
static inline bool Is8859Character(char c) {
	const unsigned char cc = static_cast<unsigned char>(c);
	return (cc >= 32 && cc <= 126) || (cc >= 160);
}

void Gzip::IsolatedInitialize(const NameValuePairs &parameters)
{
	ConstByteArrayParameter v;
	if (parameters.GetValue(Name::FileName(), v))
		m_filename.assign(reinterpret_cast<const char*>(v.begin()), v.size());
	if (parameters.GetValue(Name::Comment(), v))
		m_comment.assign(reinterpret_cast<const char*>(v.begin()), v.size());
	m_filetime = parameters.GetIntValueWithDefault(Name::FileTime(), 0);
}

void Gzip::WritePrestreamHeader()
{
	m_totalLen = 0;
	m_crc.Restart();

	int flags = 0;
	if(!m_filename.empty())
		flags |= FILENAME;
	if(!m_comment.empty())
		flags |= COMMENTS;

	AttachedTransformation()->Put(MAGIC1);
	AttachedTransformation()->Put(MAGIC2);
	AttachedTransformation()->Put(DEFLATED);
	AttachedTransformation()->Put((byte)flags);		// general flag
	AttachedTransformation()->PutWord32(m_filetime, LITTLE_ENDIAN_ORDER);	// time stamp
	byte extra = (GetDeflateLevel() == 1) ? FAST : ((GetDeflateLevel() == 9) ? SLOW : 0);
	AttachedTransformation()->Put(extra);
	AttachedTransformation()->Put(GZIP_OS_CODE);

	// Filename is NULL terminated, hence the +1
	if(!m_filename.empty())
		AttachedTransformation()->Put((const unsigned char*)m_filename.data(), m_filename.size() +1);

	// Comment is NULL terminated, hence the +1
	if(!m_comment.empty())
		AttachedTransformation()->Put((const unsigned char*)m_comment.data(), m_comment.size() +1);
}

void Gzip::ProcessUncompressedData(const byte *inString, size_t length)
{
	m_crc.Update(inString, length);
	m_totalLen += (word32)length;
}

void Gzip::WritePoststreamTail()
{
	SecByteBlock crc(4);
	m_crc.Final(crc);
	AttachedTransformation()->Put(crc, 4);
	AttachedTransformation()->PutWord32(m_totalLen, LITTLE_ENDIAN_ORDER);

	m_filetime = 0;
	m_filename.clear();
	m_comment.clear();
}

void Gzip::SetComment(const std::string& comment, bool throwOnEncodingError)
{
	if(throwOnEncodingError)
	{
		for(size_t i = 0; i < comment.length(); i++) {
			const char c = comment[i];
			if(!Is8859Character(c))
				throw InvalidDataFormat("The comment is not ISO/IEC 8859-1 encoded");
		}
	}

	m_comment = comment;
}

void Gzip::SetFilename(const std::string& filename, bool throwOnEncodingError)
{
	if(throwOnEncodingError)
	{
		for(size_t i = 0; i < filename.length(); i++) {
			const char c = filename[i];
			if(!Is8859Character(c))
				throw InvalidDataFormat("The filename is not ISO/IEC 8859-1 encoded");
		}
	}

	m_filename = filename;
}

// *************************************************************

Gunzip::Gunzip(BufferedTransformation *attachment, bool repeat, int propagation)
	: Inflator(attachment, repeat, propagation), m_length(0), m_filetime(0)
{
}

void Gunzip::ProcessPrestreamHeader()
{
	m_length = 0;
	m_crc.Restart();

	m_filetime = 0;
	m_filename.clear();
	m_comment.clear();

	byte buf[6];
	byte b, flags;

	if (m_inQueue.Get(buf, 2)!=2) throw HeaderErr();
	if (buf[0] != MAGIC1 || buf[1] != MAGIC2) throw HeaderErr();
	if (!m_inQueue.Get(b) || (b != DEFLATED)) throw HeaderErr();	 // skip CM flag
	if (!m_inQueue.Get(flags)) throw HeaderErr();
	if (flags & (ENCRYPTED | CONTINUED)) throw HeaderErr();
	if (m_inQueue.GetWord32(m_filetime, LITTLE_ENDIAN_ORDER) != 4) throw HeaderErr();
	if (m_inQueue.Skip(2)!=2) throw HeaderErr();    // Skip extra flags and OS type

	if (flags & EXTRA_FIELDS)	// skip extra fields
	{
		word16 length;
		if (m_inQueue.GetWord16(length, LITTLE_ENDIAN_ORDER) != 2) throw HeaderErr();
		if (m_inQueue.Skip(length)!=length) throw HeaderErr();
	}

	if (flags & FILENAME)	// extract filename
	{
		do
		{
			if(!m_inQueue.Get(b)) throw HeaderErr();
			if(b) m_filename.append( 1, (char)b );
		}
		while (b);
	}

	if (flags & COMMENTS)	// extract comments
	{
		do
		{
			if(!m_inQueue.Get(b)) throw HeaderErr();
			if(b) m_comment.append( 1, (char)b );
		}
		while (b);
	}
}

void Gunzip::ProcessDecompressedData(const byte *inString, size_t length)
{
	AttachedTransformation()->Put(inString, length);
	m_crc.Update(inString, length);
	m_length += (word32)length;
}

void Gunzip::ProcessPoststreamTail()
{
	SecByteBlock crc(4);
	if (m_inQueue.Get(crc, 4) != 4)
		throw TailErr();
	if (!m_crc.Verify(crc))
		throw CrcErr();

	word32 lengthCheck;
	if (m_inQueue.GetWord32(lengthCheck, LITTLE_ENDIAN_ORDER) != 4)
		throw TailErr();
	if (lengthCheck != m_length)
		throw LengthErr();
}

const std::string& Gunzip::GetComment(bool throwOnEncodingError) const
{
	if(throwOnEncodingError)
	{
		for(size_t i = 0; i < m_comment.length(); i++) {
			const char c = m_comment[i];
			if(!Is8859Character(c))
				throw InvalidDataFormat("The comment is not ISO/IEC 8859-1 encoded");
		}
	}

	return m_comment;
}

const std::string& Gunzip::GetFilename(bool throwOnEncodingError) const
{
	if(throwOnEncodingError)
	{
		for(size_t i = 0; i < m_filename.length(); i++) {
			const char c = m_filename[i];
			if(!Is8859Character(c))
				throw InvalidDataFormat("The filename is not ISO/IEC 8859-1 encoded");
		}
	}

	return m_filename;
}

NAMESPACE_END
