#pragma once

#include "Crypt.h"
#include <string>

class AES : public Crypt
{
public:
	AES();
	virtual ~AES();
	virtual bool encrypt(FILE*infile, FILE*outfile, Mode mode, const unsigned char * key) ;
	virtual bool decrypt(FILE*infile, FILE*outfile, Mode mode, const unsigned char* key) ;
protected:
	class Key
	{
	public:
		bool init(KeyLengthInBits keyLengthInBits, const unsigned char* key);
		unsigned char* key;
		int keyLengthInBytes;
		int keyLengthInBits;
		int keyLengthInLong;
	protected:
		bool keyExpansion(const unsigned char* key, int keyLengthInBytes);
		unsigned char expandedKey[ 15 * 8 * 4];
	};
	class SBox
	{
	public:
		static const unsigned char sBox[256];
		static const unsigned char invSBox[256];
	};
	static const unsigned char gf2_8_mult_09[256];
	static const unsigned char gf2_8_mult_0b[256];
	static const unsigned char gf2_8_mult_0d[256];
	static const unsigned char gf2_8_mult_0e[256];
	static const unsigned char gf2_8_inv[256];
	static const unsigned char rcon[256];
	bool expandKey();
	bool doPreRound(unsigned char * inblock, unsigned char * outblock, int blockSize);
	bool doMainRounds(unsigned char * inblock, unsigned char * outblock, int blockSize);
	bool doLastRound(unsigned char * inblock, unsigned char * outblock, int blockSize);
	
	bool substituteBytes(unsigned char * inblock, unsigned char * outblock, int blockSize);
	bool shiftRows(unsigned char * inblock, unsigned char * outblock, int blockSize);
	bool mixColumns(unsigned char * inblock, unsigned char * outblock, int blockSize);
	bool addRoundKey(unsigned char * inblock, unsigned char * outblock, int blockSize,Key & key);

	bool doXOR(unsigned char * inblock, unsigned char * outblock, int size, Key & key);
	unsigned long SubstituteBytesSBox(unsigned long data);

	Key key;
	Key * keyArray;
	int numberOfRounds;
	unsigned char * blockBuffer1;
	unsigned char * blockBuffer2;
	unsigned char * keyBuffer;
	//unsigned char * inblock;
	//unsigned char * outblock;
	int blockSizeInBytes;
	int blockSizeInBits;
	int blockSizeInLong;
	int keySizeInLong;
	int keySizeInBytes;
	int keySizeInBits;
	SBox sbox;
};

