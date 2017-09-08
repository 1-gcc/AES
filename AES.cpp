#include "AES.h"

#define RotateRight(x) ((x) >> 8 | (x) << 24)

unsigned long AES::SubstituteBytesSBox(unsigned long data)
{
	unsigned long result = 0;
	result = AES::SBox::sBox[data >> 24];
	result <<= 8;
	result |= AES::SBox::sBox[(data >> 16) & 255];
	result <<= 8;
	result |= AES::SBox::sBox[(data >> 8) & 255];
	result <<= 8;
	result |= AES::SBox::sBox[data & 255];
	return result;
}

AES::AES()
{
	blockSizeInBits = 128;
	blockSizeInBytes = 16;
	blockSizeInLong = 4;
	blockBuffer1 = NULL;
	blockBuffer2 = NULL;
	blockBuffer1 = new unsigned char[blockSizeInBytes];
	blockBuffer2 = new unsigned char[blockSizeInBytes];
	keyBuffer = NULL;
	keyArray = NULL;
}


AES::~AES()
{
	if (blockBuffer1)
		delete blockBuffer1;
	if (blockBuffer2)
		delete blockBuffer2;
	if(keyArray)
		delete keyArray;
}
//bool AES::doRound()

void swapPointers(unsigned char*&in, unsigned char*&out)
{
	unsigned char* help = in;
	in = out;
	out = help;
}
bool AES::doMainRounds(unsigned char * inblock, unsigned char * outblock,int blockSize)
{
	for (int r = 1; r < numberOfRounds - 1; r++)
	{
		substituteBytes(inblock,outblock,blockSize);
		swapPointers(inblock, outblock);
		shiftRows(inblock, outblock, blockSize);
		swapPointers(inblock, outblock);
		mixColumns(inblock, outblock, blockSize);
		swapPointers(inblock, outblock);
		addRoundKey(inblock, outblock, blockSize,keyArray[r]);
		if(r < numberOfRounds - 1)
			swapPointers(inblock, outblock);
	}
	return true;
}
bool AES::expandKey()
{
	
	
	keyArray = new Key[numberOfRounds + 1];
	keyBuffer = new unsigned char[(numberOfRounds + 1)*key.keyLengthInBytes];
	memcpy(keyBuffer, key.key, key.keyLengthInBytes );
	unsigned long temp;
	unsigned long *Wb = reinterpret_cast<unsigned long*>(keyBuffer); // todo not portable - Endian problems
	int Nk = key.keyLengthInLong;
	int Nb = this->blockSizeInLong;
	int Nr = numberOfRounds;
	if (Nk <= 6)
	{
		for (int i = Nk; i < Nb*(Nr + 1); i++)
		{
			temp = Wb[i - 1];
			if ((i%Nk) == 0)
				temp = SubstituteBytesSBox(RotateRight(temp)) ^ rcon[i / Nk];
			Wb[i] = Wb[i - Nk] ^ temp;
		}
	}
	else
	{
		for (int i = Nk; i < Nb*(Nr + 1); i++)
		{
			temp = Wb[i - 1];
			if ((i%Nk) == 0)
				temp = SubstituteBytesSBox(RotateRight(temp)) ^ rcon[i / Nk];
			else if ((i%Nk) == 4)
				temp = SubstituteBytesSBox(temp);
			Wb[i] = Wb[i - Nk] ^ temp;
		}
	}


	return true;

}
bool AES::doPreRound(unsigned char * inblock, unsigned char * outblock,int blockSize)
{
	addRoundKey(inblock, outblock, blockSize, keyArray[0]);
	return true;
}
bool AES::doLastRound(unsigned char * inblock, unsigned char * outblock, int blockSize)
{
	substituteBytes(inblock,outblock,blockSize);
	swapPointers(inblock, outblock);
	shiftRows(inblock, outblock, blockSize);
	swapPointers(inblock, outblock);
	// don't mixColumns();
	addRoundKey(inblock,outblock,blockSize,keyArray[numberOfRounds - 1]);
	return true;
}
bool AES::substituteBytes(unsigned char * inblock,unsigned char * outblock,int blockSize)
{
	for (int i = 0; i < blockSize; ++i)
	{
		outblock[i] = sbox.sBox[inblock[i]];
	}
	return true;
}
bool AES::shiftRows(unsigned char * inblock, unsigned char * outblock, int blockSize)
{
	return true;
}
bool AES::mixColumns(unsigned char * inblock, unsigned char * outblock, int blockSize)
{
	return true;
}
bool AES::addRoundKey(unsigned char * inblock, unsigned char * outblock, int blockSize,Key & key)
{
	doXOR(inblock, outblock,blockSize,key);
	return true;
}
bool AES::doXOR(unsigned char*inblock, unsigned char*outblock, int size, Key & key)
{

	return true;
}
bool AES::encrypt(FILE*infile, FILE*outfile, Mode mode, const unsigned char * key)
{
	this->key.init(mode.lengthKey, key);
	switch (mode.lengthKey)
	{
	case AES_128:
		numberOfRounds = 10;
		break;
	case AES_192:
		numberOfRounds = 12;
		break;
	case AES_256:
		numberOfRounds = 14;
		break;
	}
	unsigned char* inblock = blockBuffer1;
	unsigned char * outblock = blockBuffer2;
	
	expandKey();
	doPreRound(inblock, outblock,blockSizeInBytes);
	swapPointers(inblock, outblock);
	doMainRounds(inblock, outblock, blockSizeInBytes);
	swapPointers(inblock, outblock);
	doLastRound(inblock, outblock, blockSizeInBytes);
	delete blockBuffer1;
	delete blockBuffer2;
	blockBuffer1 = NULL;
	blockBuffer2 = NULL;
	return true;
}
bool AES::decrypt(FILE*infile, FILE*outfile, Mode mode, const unsigned char* key)
{

	return true;
}
bool AES::Key::init(KeyLengthInBits keyLengthInBits, const unsigned char* key)
{
	keyLengthInBytes = keyLengthInBits*8;
	this->keyLengthInBits = keyLengthInBits;
	keyLengthInLong = keyLengthInBits * 8 * 4 ;


	return keyExpansion(key, keyLengthInBytes);
}
bool AES::Key::keyExpansion(const unsigned char* key, int lengthKeyInBytes)
{
	throw 1;
	return true;
}
unsigned char BitSumMod2(unsigned char value)
{ // returns the bitsum mod 2 of value
	value = (value >> 4) ^ (value & 15);
	value = (value >> 2) ^ (value & 3);
	return (value >> 1) ^ (value & 1);
}


#ifdef NEVER
void AES::encryptBlock(const BYTE * blockIn, BYTE * blockOut,int blockSize)
{ 
	unsigned long state[8 * 2]; // 2 buffers
	unsigned long * r_ptr = reinterpret_cast<unsigned long*>(W);
	unsigned long * dest = state;
	unsigned long * src = state;
	const unsigned long * datain = reinterpret_cast<const unsigned long*>(blockIn);
	unsigned long * dataout = reinterpret_cast<unsigned long*>(blockOut);

	if (Nb == 4)
	{
		AddRoundKey4(dest, datain);

		if (Nr == 14)
		{
			Round4(dest, src);
			Round4(src, dest);
			Round4(dest, src);
			Round4(src, dest);
		}
		else if (Nr == 12)
		{
			Round4(dest, src);
			Round4(src, dest);
		}

		Round4(dest, src);
		Round4(src, dest);
		Round4(dest, src);
		Round4(src, dest);
		Round4(dest, src);
		Round4(src, dest);
		Round4(dest, src);
		Round4(src, dest);
		Round4(dest, src);

		FinalRound4(dataout, dest);
	}
	else if (Nb == 6)
	{
		AddRoundKey6(dest, datain);

		if (Nr == 14)
		{
			Round6(dest, src);
			Round6(src, dest);
		}

		Round6(dest, src);
		Round6(src, dest);
		Round6(dest, src);
		Round6(src, dest);
		Round6(dest, src);
		Round6(src, dest);
		Round6(dest, src);
		Round6(src, dest);
		Round6(dest, src);
		Round6(src, dest);
		Round6(dest, src);

		FinalRound6(dataout, dest);
	}
	else // Nb == 8
	{
		AddRoundKey8(dest, datain);

		Round8(dest, src);
		Round8(src, dest);
		Round8(dest, src);
		Round8(src, dest);
		Round8(dest, src);
		Round8(src, dest);
		Round8(dest, src);
		Round8(src, dest);
		Round8(dest, src);
		Round8(src, dest);
		Round8(dest, src);
		Round8(src, dest);
		Round8(dest, src);

		FinalRound8(dataout, dest);
	} // end switch on Nb

} // Encrypt
#endif