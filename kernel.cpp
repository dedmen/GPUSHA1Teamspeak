/*
    SHA1 OpenCL Optimized kernel
    (c) B. Kerler 2018
    MIT License
*/

/*
    (small) Changes:
    outbuf and inbuf structs defined using the buffer_structs_template
    func_sha1 renamed to hash_main
    hash array trimmed to size 5
*/

#define MyOmega "MEXXgaMh3pncQ=="

#pragma OPENCL EXTENSION cl_khr_int64_base_atomics: enable

// https://github.com/mohaps/TinySHA1

struct SHA1State {

    unsigned int m_digest[5];
    unsigned char m_block[64];
    size_t m_blockByteIndex;
    size_t m_byteCount;
};

void sha1_reset(struct SHA1State* state) {
    state->m_digest[0] = 0x67452301;
    state->m_digest[1] = 0xEFCDAB89;
    state->m_digest[2] = 0x98BADCFE;
    state->m_digest[3] = 0x10325476;
    state->m_digest[4] = 0xC3D2E1F0;
    state->m_blockByteIndex = 0;
    state->m_byteCount = 0;
}

void sha1_processBlock(struct SHA1State* state) {
    unsigned int w[80];
    for (size_t i = 0; i < 16; i++) {
        w[i] = (state->m_block[i * 4 + 0] << 24);
        w[i] |= (state->m_block[i * 4 + 1] << 16);
        w[i] |= (state->m_block[i * 4 + 2] << 8);
        w[i] |= (state->m_block[i * 4 + 3]);
    }
    for (size_t i = 16; i < 80; i++) {
        w[i] = rotate((unsigned int)(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]), (unsigned int)1u);
    }

    unsigned int a = state->m_digest[0];
    unsigned int b = state->m_digest[1];
    unsigned int c = state->m_digest[2];
    unsigned int d = state->m_digest[3];
    unsigned int e = state->m_digest[4];

    for (unsigned int i = 0; i < 80; ++i) {
        unsigned int f = 0;
        unsigned int k = 0;

        if (i < 20) {
            f = (b & c) | (~b & d);
            k = 0x5A827999;
        }
        else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1;
        }
        else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDC;
        }
        else {
            f = b ^ c ^ d;
            k = 0xCA62C1D6;
        }
        unsigned int temp = rotate(a, (unsigned int)5) + f + e + k + w[i];
        e = d;
        d = c;
        c = rotate(b, (unsigned int)30u);
        b = a;
        a = temp;
    }

    state->m_digest[0] += a;
    state->m_digest[1] += b;
    state->m_digest[2] += c;
    state->m_digest[3] += d;
    state->m_digest[4] += e;
}

void sha1_processByte(struct SHA1State* state, unsigned char octet) {
    state->m_block[state->m_blockByteIndex++] = octet;
    ++state->m_byteCount;
    if (state->m_blockByteIndex == 64) {
        state->m_blockByteIndex = 0;
        sha1_processBlock(state);
    }
}

void sha1_processBlockRange(struct SHA1State* state, const void* const start, const void* const end) {
    const unsigned char* begin = (const unsigned char*)(start);
    const unsigned char* finish = (const unsigned char*)(end);
    while (begin != finish) {
        sha1_processByte(state, *begin);
        begin++;
    }
}

void sha1_processBytes(struct SHA1State* state, const void* const data, unsigned int len) {
    const unsigned char* block = (const unsigned char*)(data);
    sha1_processBlockRange(state, block, block + len);
}

void sha1_getDigest(struct SHA1State* state, unsigned int* digest) {
    unsigned int bitCount = state->m_byteCount * 8;
    sha1_processByte(state, 0x80);
    if (state->m_blockByteIndex > 56) {
        while (state->m_blockByteIndex != 0) {
            sha1_processByte(state, 0);
        }
        while (state->m_blockByteIndex < 56) {
            sha1_processByte(state, 0);
        }
    }
    else {
        while (state->m_blockByteIndex < 56) {
            sha1_processByte(state, 0);
        }
    }
    sha1_processByte(state, 0);
    sha1_processByte(state, 0);
    sha1_processByte(state, 0);
    sha1_processByte(state, 0);
    sha1_processByte(state, (unsigned char)((bitCount >> 24) & 0xFF));
    sha1_processByte(state, (unsigned char)((bitCount >> 16) & 0xFF));
    sha1_processByte(state, (unsigned char)((bitCount >> 8) & 0xFF));
    sha1_processByte(state, (unsigned char)((bitCount) & 0xFF));

    digest[0] = state->m_digest[0];
    digest[1] = state->m_digest[1];
    digest[2] = state->m_digest[2];
    digest[3] = state->m_digest[3];
    digest[4] = state->m_digest[4];
}

struct HashState {
    unsigned int State[5];
    int curloop;
    int loops;
    int length;
#if _DEBUG
    unsigned int W[0x10];
    int plen;
#endif
};


__global struct SHA1State StoredHashState;

typedef struct {
    ulong buffer;
} inbuf;

typedef struct {
    ulong idx;
    unsigned int count;
    //unsigned int buffer[0x20];
} outbuf;

//https://github.com/wyaneva/clClibc/blob/master/cl-string.h

char* strcpyGen(char* dest, char* source) {
    char* destptr = dest;
    do {
        *destptr = *source++;
    } while (*destptr++);

    return destptr;
}


char* strcpy(char* dest, __private char* source) {
    char* destptr = dest;
    do {
        *destptr = *source++;
    } while (*destptr++);

    return destptr;
}

char* strcpyGlob(char* dest, __global char* source) {
    char* destptr = dest;
    do {
        *destptr = *source++;
    } while (*destptr++);

    return destptr;
}


char* strcpyCst(char* dest, __constant char* source) {
    char* destptr = dest;
    do {
        *destptr = *source++;
    } while (*destptr++);

    return destptr;
}

char* strcpyPrivToGlob(__global char* dest, char* source) {
    char* destptr = dest;
    do {
        *destptr = *source++;
    } while (*destptr++);

    return destptr;
}



/* A utility function to reverse a string  */
void reverse(char* str, int length)
{
    int start = 0;
    int end = length - 1;
    while (start < end) {
        char x = *(str + start);
        *(str + start) = *(str + end);
        *(str + end) = x;
        start++;
        end--;
    }
}

// Implementation of itoa() 
char* itoa(ulong num, char* str) {
    ulong i = 0;
    //bool isNegative = false;

    /* Handle 0 explicitely, otherwise empty string is printed for 0 */
    if (num == 0) {
        str[i++] = '0';
        str[i] = '\0';
        return str;
    }

    // In standard itoa(), negative numbers are handled only with  
    // base 10. Otherwise numbers are considered unsigned. 
    //if (num < 0) {
    //    isNegative = true;
    //    num = -num;
    //}

    // Process individual digits 
    while (num != 0)
    {
        ulong rem = num % 10;
        str[i++] = (rem > 9) ? (rem - 10) + 'a' : rem + '0';
        num = num / 10;
    }

    // If number is negative, append '-' 
    //if (isNegative)
    //    str[i++] = '-';

    str[i] = '\0'; // Append string terminator 

    // Reverse the string 
    reverse(str, i);

    return str;
}


__private unsigned int CountLeadingZero(__private const unsigned int* buffer) {
    __private unsigned int lastCount = 0;
    __private unsigned int result = 0;
    __private unsigned int idx = 0;
    do {
        unsigned int val = buffer[idx];
        if (val == 0)
            lastCount = 32;
        else
            lastCount = clz(val);
        result += lastCount;
        idx++;
    } while (lastCount == 32);
    return result;
}


__kernel void prepareHashStates(__global struct SHA1State* stateBuffer) {

    __private unsigned int buffer[0x20] = { 0xffffffff };

    char* bufferArray = (char*)&buffer;

    strcpyCst(bufferArray, MyOmega);


    sha1_reset(&StoredHashState);
    sha1_processBytes(&StoredHashState, buffer, 108);
   
    stateBuffer[0] = StoredHashState;
}


typedef struct {
    ulong idx;
    unsigned int count;
    char textBuf[180];
    unsigned int buffer[0x10];

    struct HashState state;
} outbufDebug;


__kernel void HashTest(__global unsigned int* inputString, ulong inputLength, __global outbufDebug* outbuffer)
{
    __private unsigned int hashbuffer[0x5] = { 0 };

    __private unsigned int buffer[0x20] = { 0x00000000 };

    char* bufferArray = (char*)&buffer;

    strcpyGlob(bufferArray, inputString);

    __private struct SHA1State state;
    sha1_reset(&state);
    sha1_processBytes(&state, buffer, inputLength);
    sha1_getDigest(&state, hashbuffer);

    strcpyGen(outbuffer[0].textBuf, (char*)inputString);


    outbuffer[0].buffer[0x0] = hashbuffer[0x0];
    outbuffer[0].buffer[0x1] = hashbuffer[0x1];
    outbuffer[0].buffer[0x2] = hashbuffer[0x2];
    outbuffer[0].buffer[0x3] = hashbuffer[0x3];
    outbuffer[0].buffer[0x4] = hashbuffer[0x4];
    outbuffer[0].buffer[0xd] = (unsigned int)rotate((unsigned int)0x12345678, (unsigned int)5);
    outbuffer[0].buffer[0xe] = (unsigned int)rotate((unsigned int)0x12345678, (unsigned int)30);
    outbuffer[0].buffer[0xf] = (unsigned int)bitselect((unsigned int)0x12345678, (unsigned int)0xffffffff, (unsigned int)0x00000000);
    outbuffer[0].count = CountLeadingZero(hashbuffer);


}


__kernel void SingleHash(ulong number, __global outbufDebug* outbuffer)
{

    __private unsigned int buffer[0x20] = { 0xffffffff };

    char* bufferArray = (char*)&buffer;

    strcpyCst(bufferArray, MyOmega);
    char* numberDest = &(bufferArray[108]);
    __private char numberSource[16] = { 0 };
    itoa(number, numberSource);
    __private unsigned int length = (strcpy(numberDest, numberSource) - (__private char*) & buffer) - 1;
    // unsigned int hash[20/4]={0};

    __private unsigned int hashbuffer[0x5] = { 0 };

    __private struct SHA1State state;



    state = StoredHashState;
    sha1_processBytes(&state, numberSource, length - 108);


    //sha1_reset(&state);
    //sha1_processBytes(&state, buffer, length);


    sha1_getDigest(&state, hashbuffer);







    outbuffer[0].idx = number;

    strcpyPrivToGlob(outbuffer[0].textBuf, bufferArray);


    outbuffer[0].buffer[0x0] = hashbuffer[0x0];
    outbuffer[0].buffer[0x1] = hashbuffer[0x1];
    outbuffer[0].buffer[0x2] = hashbuffer[0x2];
    outbuffer[0].buffer[0x3] = hashbuffer[0x3];
    outbuffer[0].buffer[0x4] = hashbuffer[0x4];
    outbuffer[0].count = CountLeadingZero(hashbuffer);

}




__kernel void hash_main(ulong baseNumber, __global outbuf* outbuffer)
{
    unsigned int globalID = get_global_id(0);
    unsigned int idx = get_local_id(0);
    ulong number = baseNumber + globalID;

    __private unsigned int buffer[0x20] = {0xffffffff};

    char* bufferArray = (char*) &buffer;

    strcpyCst(bufferArray, MyOmega);
    char* numberDest = &(bufferArray[108]);
    __private char numberSource[16] = {0};
    itoa(number, numberSource);
   __private unsigned int length = (strcpy(numberDest, numberSource) - (__private char*)&buffer) - 1;
    // unsigned int hash[20/4]={0};

   __private unsigned int hashbuffer[0x5] = {0};


   //hash_global(buffer, length, hashbuffer);



   __private struct SHA1State state;

   state = StoredHashState;
   sha1_processBytes(&state, numberSource, length - 108);


   //sha1_reset(&state);
   //sha1_processBytes(&state, buffer, length);



   sha1_getDigest(&state, hashbuffer);


   //HashFromState(buffer, length, hashbuffer, &StoredHashState);

   
    //outbuffer[32].idx = number;


    //if (number == 24340904160ul) {
    //    outbuffer[33].buffer[0x0] = buffer[0x0];
    //    outbuffer[33].buffer[0x1] = buffer[0x1];
    //    outbuffer[33].buffer[0x2] = buffer[0x2];
    //    outbuffer[33].buffer[0x3] = buffer[0x3];
    //    outbuffer[33].buffer[0x4] = buffer[0x4];
    //    outbuffer[33].buffer[0x5] = buffer[0x5];
    //    outbuffer[33].buffer[0x6] = buffer[0x6];
    //    outbuffer[33].buffer[0x7] = buffer[0x7];
    //    outbuffer[33].buffer[0x8] = buffer[0x8];
    //    outbuffer[33].buffer[0x9] = buffer[0x9];
    //    outbuffer[33].buffer[0xa] = buffer[0xa];
    //    outbuffer[33].buffer[0xb] = buffer[0xb];
    //    outbuffer[33].buffer[0xc] = buffer[0xc];
    //    outbuffer[33].buffer[0xd] = buffer[0xd];
    //    outbuffer[33].buffer[0xe] = buffer[0xe];
    //    outbuffer[33].buffer[0xf] = buffer[0xf];
    //    outbuffer[33].buffer[0x10] = buffer[0x10];
    //    outbuffer[33].buffer[0x11] = buffer[0x11];
    //    outbuffer[33].buffer[0x12] = buffer[0x12];
    //    outbuffer[33].buffer[0x13] = buffer[0x13];
    //    outbuffer[33].buffer[0x14] = buffer[0x14];
    //    outbuffer[33].buffer[0x15] = buffer[0x15];
    //    outbuffer[33].buffer[0x16] = buffer[0x16];
    //    outbuffer[33].buffer[0x17] = buffer[0x17];
    //    outbuffer[33].buffer[0x18] = buffer[0x18];
    //    outbuffer[33].buffer[0x19] = buffer[0x19];
    //    outbuffer[33].buffer[0x1a] = buffer[0x1a];
    //    outbuffer[33].buffer[0x1b] = buffer[0x1b];
    //    outbuffer[33].buffer[0x1c] = buffer[0x1c];
    //    outbuffer[33].buffer[0x1d] = buffer[0x1d];
    //    outbuffer[33].buffer[0x1e] = buffer[0x1e];
    //    outbuffer[33].buffer[0x1f] = buffer[0x1f];
    //    outbuffer[33].count = CountLeadingZero(hashbuffer);
    //
    //
    //    outbuffer[34].buffer[0x0] = hashbuffer[0x0];
    //    outbuffer[34].buffer[0x1] = hashbuffer[0x1];
    //    outbuffer[34].buffer[0x2] = hashbuffer[0x2];
    //    outbuffer[34].buffer[0x3] = hashbuffer[0x3];
    //    outbuffer[34].buffer[0x4] = hashbuffer[0x4];
    //    outbuffer[34].buffer[0x5] = hashbuffer[0x5];
    //    outbuffer[34].buffer[0x6] = hashbuffer[0x6];
    //    outbuffer[34].buffer[0x7] = hashbuffer[0x7];
    //    outbuffer[34].buffer[0x8] = hashbuffer[0x8];
    //    outbuffer[34].buffer[0x9] = hashbuffer[0x9];
    //    outbuffer[34].buffer[0xa] = hashbuffer[0xa];
    //    outbuffer[34].buffer[0xb] = hashbuffer[0xb];
    //    outbuffer[34].buffer[0xc] = hashbuffer[0xc];
    //    outbuffer[34].buffer[0xd] = hashbuffer[0xd];
    //    outbuffer[34].buffer[0xe] = hashbuffer[0xe];
    //    outbuffer[34].buffer[0xf] = hashbuffer[0xf];
    //    outbuffer[34].buffer[0x10] = hashbuffer[0x10];
    //    outbuffer[34].buffer[0x11] = hashbuffer[0x11];
    //    outbuffer[34].buffer[0x12] = hashbuffer[0x12];
    //    outbuffer[34].buffer[0x13] = hashbuffer[0x13];
    //    outbuffer[34].buffer[0x14] = hashbuffer[0x14];
    //    outbuffer[34].buffer[0x15] = hashbuffer[0x15];
    //    outbuffer[34].buffer[0x16] = hashbuffer[0x16];
    //    outbuffer[34].buffer[0x17] = hashbuffer[0x17];
    //    outbuffer[34].buffer[0x18] = hashbuffer[0x18];
    //    outbuffer[34].buffer[0x19] = hashbuffer[0x19];
    //    outbuffer[34].buffer[0x1a] = hashbuffer[0x1a];
    //    outbuffer[34].buffer[0x1b] = hashbuffer[0x1b];
    //    outbuffer[34].buffer[0x1c] = hashbuffer[0x1c];
    //    outbuffer[34].buffer[0x1d] = hashbuffer[0x1d];
    //    outbuffer[34].buffer[0x1e] = hashbuffer[0x1e];
    //    outbuffer[34].buffer[0x1f] = hashbuffer[0x1f];
    //}

    if (CountLeadingZero(hashbuffer) < 35) return;

    for (int i = 0; i < 128; ++i) {
        if (atomic_cmpxchg(&outbuffer[i].idx, 0, number) == 0) {
            outbuffer[i].idx = number;
            outbuffer[i].count = CountLeadingZero(hashbuffer);
            return;
        }
    }


    //outbuffer[idx].buffer[0x0] = hashbuffer[0x0];
    //outbuffer[idx].buffer[0x1] = hashbuffer[0x1];
    //outbuffer[idx].buffer[0x2] = hashbuffer[0x2];
    //outbuffer[idx].buffer[0x3] = hashbuffer[0x3];
    //outbuffer[idx].buffer[0x4] = hashbuffer[0x4];
    //outbuffer[idx].buffer[0x5] = hashbuffer[0x5];
    //outbuffer[idx].buffer[0x6] = hashbuffer[0x6];
    //outbuffer[idx].buffer[0x7] = hashbuffer[0x7];
    //outbuffer[idx].buffer[0x8] = hashbuffer[0x8];
    //outbuffer[idx].buffer[0x9] = hashbuffer[0x9];
    //outbuffer[idx].buffer[0xa] = hashbuffer[0xa];
    //outbuffer[idx].buffer[0xb] = hashbuffer[0xb];
    //outbuffer[idx].buffer[0xc] = hashbuffer[0xc];
    //outbuffer[idx].buffer[0xd] = hashbuffer[0xd];
    //outbuffer[idx].buffer[0xe] = hashbuffer[0xe];
    //outbuffer[idx].buffer[0xf] = hashbuffer[0xf];
    //outbuffer[idx].buffer[0x10] = hashbuffer[0x10];
    //outbuffer[idx].buffer[0x11] = hashbuffer[0x11];
    //outbuffer[idx].buffer[0x12] = hashbuffer[0x12];
    //outbuffer[idx].buffer[0x13] = hashbuffer[0x13];
    //outbuffer[idx].buffer[0x14] = hashbuffer[0x14];
    //outbuffer[idx].buffer[0x15] = hashbuffer[0x15];
    //outbuffer[idx].buffer[0x16] = hashbuffer[0x16];
    //outbuffer[idx].buffer[0x17] = hashbuffer[0x17];
    //outbuffer[idx].buffer[0x18] = hashbuffer[0x18];
    //outbuffer[idx].buffer[0x19] = hashbuffer[0x19];
    //outbuffer[idx].buffer[0x1a] = hashbuffer[0x1a];
    //outbuffer[idx].buffer[0x1b] = hashbuffer[0x1b];
    //outbuffer[idx].buffer[0x1c] = hashbuffer[0x1c];
    //outbuffer[idx].buffer[0x1d] = hashbuffer[0x1d];
    //outbuffer[idx].buffer[0x1e] = hashbuffer[0x1e];
    //outbuffer[idx].buffer[0x1f] = CountLeadingZero(hashbuffer);

    //unsigned int firstRes = outbuffer[idx].buffer[0];
    //outbuffer[idx].buffer[1] = firstRes;
    //outbuffer[idx].buffer[2] = clz(firstRes);
    //outbuffer[idx].buffer[3] = 31 - clz(firstRes & -firstRes);


    
    /*     outbuffer[idx].buffer[0]=hash[0];
        outbuffer[idx].buffer[1]=hash[1];
        outbuffer[idx].buffer[2]=hash[2];
        outbuffer[idx].buffer[3]=hash[3];
        outbuffer[idx].buffer[4]=hash[4]; */
}


__kernel void vector_add(__global const int* A, __global const int* B, __global int* C) {

    // Get the index of the current element to be processed
    int i = get_global_id(0);

    // Do the operation
    C[i] = A[i] + B[i];
}