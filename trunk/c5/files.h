#ifndef CRYPTOPP_FILES_H
#define CRYPTOPP_FILES_H

#include "cryptlib.h"
#include "filters.h"
#include "argnames.h"

#include <iostream>
#include <fstream>

NAMESPACE_BEGIN(CryptoPP)

//! file-based implementation of Store interface
class CRYPTOPP_DLL FileStore : public Store, private FilterPutSpaceHelper, public NotCopyable
{
public:
	class Err : public Exception
	{
	public:
		Err(const std::string &s) : Exception(IO_ERROR, s) {}
	};
	class OpenErr : public Err {public: OpenErr(const std::string &filename) : Err("FileStore: error opening file for reading: " + filename) {}};
	class ReadErr : public Err {public: ReadErr() : Err("FileStore: error reading file") {}};

	FileStore() : m_stream(NULL) {}
	FileStore(std::istream &in)
		{StoreInitialize(MakeParameters(Name::InputStreamPointer(), &in));}
	FileStore(const char *filename)
		{StoreInitialize(MakeParameters(Name::InputFileName(), filename));}

	std::istream* GetStream() {return m_stream;}

	unsigned long MaxRetrievable() const;
	unsigned int TransferTo2(BufferedTransformation &target, unsigned long &transferBytes, const std::string &channel=NULL_CHANNEL, bool blocking=true);
	unsigned int CopyRangeTo2(BufferedTransformation &target, unsigned long &begin, unsigned long end=ULONG_MAX, const std::string &channel=NULL_CHANNEL, bool blocking=true) const;
	unsigned long Skip(unsigned long skipMax=ULONG_MAX);

private:
	void StoreInitialize(const NameValuePairs &parameters);
	
	member_ptr<std::ifstream> m_file;
	std::istream *m_stream;
	byte *m_space;
	unsigned int m_len;
	bool m_waiting;
};

//! file-based implementation of Source interface
class CRYPTOPP_DLL FileSource : public SourceTemplate<FileStore>
{
public:
	typedef FileStore::Err Err;
	typedef FileStore::OpenErr OpenErr;
	typedef FileStore::ReadErr ReadErr;

	FileSource(BufferedTransformation *attachment = NULL)
		: SourceTemplate<FileStore>(attachment) {}
	FileSource(std::istream &in, bool pumpAll, BufferedTransformation *attachment = NULL)
		: SourceTemplate<FileStore>(attachment) {SourceInitialize(pumpAll, MakeParameters(Name::InputStreamPointer(), &in));}
	FileSource(const char *filename, bool pumpAll, BufferedTransformation *attachment = NULL, bool binary=true)
		: SourceTemplate<FileStore>(attachment) {SourceInitialize(pumpAll, MakeParameters(Name::InputFileName(), filename)(Name::InputBinaryMode(), binary));}

	std::istream* GetStream() {return m_store.GetStream();}
};

//! file-based implementation of Sink interface
class CRYPTOPP_DLL FileSink : public Sink, public NotCopyable
{
public:
	class Err : public Exception
	{
	public:
		Err(const std::string &s) : Exception(IO_ERROR, s) {}
	};
	class OpenErr : public Err {public: OpenErr(const std::string &filename) : Err("FileSink: error opening file for writing: " + filename) {}};
	class WriteErr : public Err {public: WriteErr() : Err("FileSink: error writing file") {}};

	FileSink() : m_stream(NULL) {}
	FileSink(std::ostream &out)
		{IsolatedInitialize(MakeParameters(Name::OutputStreamPointer(), &out));}
	FileSink(const char *filename, bool binary=true)
		{IsolatedInitialize(MakeParameters(Name::OutputFileName(), filename)("OutputBinaryMode", binary));}

	std::ostream* GetStream() {return m_stream;}

	void IsolatedInitialize(const NameValuePairs &parameters);
	unsigned int Put2(const byte *inString, unsigned int length, int messageEnd, bool blocking);
	bool IsolatedFlush(bool hardFlush, bool blocking);

private:
	member_ptr<std::ofstream> m_file;
	std::ostream *m_stream;
};

NAMESPACE_END

#endif
