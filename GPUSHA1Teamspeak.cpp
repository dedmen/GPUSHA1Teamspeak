#include <stdio.h>
#include <stdlib.h>
#include <cstring>
#include <string_view>
#include <chrono>

#ifdef __APPLE__
#include <OpenCL/opencl.h>
#else
#include <CL/cl.h>
#endif

#define MAX_SOURCE_SIZE (0x100000)

typedef struct {
    cl_ulong buffer;
} inbuf;

typedef struct {
    cl_ulong idx;
    unsigned int count;
    //union {
    //    unsigned int buffer[0x20];
    //    unsigned char charBuf[0x20 * 4];
    //};
} outbuf;


#include <intrin.h>
unsigned rotate(unsigned n, int c)
{
    //return __builtin_ia32_rorhi(x, 7);  // 16-bit rotate, GNU C
    return _rotl(n, c);  // gcc, icc, msvc.  Intel-defined.
    //return __rold(x, n);  // gcc, icc.
    // can't find anything for clang
}


// https://github.com/mohaps/TinySHA1
#ifndef _TINY_SHA1_HPP_
#define _TINY_SHA1_HPP_
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdint.h>
namespace sha1
{
    class SHA1
    {
    public:
        typedef uint32_t digest32_t[5];
        inline static uint32_t LeftRotate(uint32_t value, size_t count) {
            return (value << count) ^ (value >> (32 - count));
        }
        SHA1() { reset(); }
        virtual ~SHA1() {}
        SHA1(const SHA1& s) { *this = s; }
        const SHA1& operator = (const SHA1& s) {
            memcpy(m_digest, s.m_digest, 5 * sizeof(uint32_t));
            memcpy(m_block, s.m_block, 64);
            m_blockByteIndex = s.m_blockByteIndex;
            m_byteCount = s.m_byteCount;
            return *this;
        }
        SHA1& reset() {
            m_digest[0] = 0x67452301;
            m_digest[1] = 0xEFCDAB89;
            m_digest[2] = 0x98BADCFE;
            m_digest[3] = 0x10325476;
            m_digest[4] = 0xC3D2E1F0;
            m_blockByteIndex = 0;
            m_byteCount = 0;
            return *this;
        }
        SHA1& processByte(uint8_t octet) {
            this->m_block[this->m_blockByteIndex++] = octet;
            ++this->m_byteCount;
            if (m_blockByteIndex == 64) {
                this->m_blockByteIndex = 0;
                processBlock();
            }
            return *this;
        }
        SHA1& processBlock(const void* const start, const void* const end) {
            const uint8_t* begin = static_cast<const uint8_t*>(start);
            const uint8_t* finish = static_cast<const uint8_t*>(end);
            while (begin != finish) {
                processByte(*begin);
                begin++;
            }
            return *this;
        }
        SHA1& processBytes(const void* const data, size_t len) {
            const uint8_t* block = static_cast<const uint8_t*>(data);
            processBlock(block, block + len);
            return *this;
        }




        const uint32_t* getDigest(digest32_t digest) {
            size_t bitCount = this->m_byteCount * 8;
            processByte(0x80);
            if (this->m_blockByteIndex > 56) {
                while (m_blockByteIndex != 0) {
                    processByte(0);
                }
                while (m_blockByteIndex < 56) {
                    processByte(0);
                }
            }
            else {
                while (m_blockByteIndex < 56) {
                    processByte(0);
                }
            }
            processByte(0);
            processByte(0);
            processByte(0);
            processByte(0);
            processByte(static_cast<unsigned char>((bitCount >> 24) & 0xFF));
            processByte(static_cast<unsigned char>((bitCount >> 16) & 0xFF));
            processByte(static_cast<unsigned char>((bitCount >> 8) & 0xFF));
            processByte(static_cast<unsigned char>((bitCount) & 0xFF));

            memcpy(digest, m_digest, 5 * sizeof(uint32_t));
            return digest;
        }
    protected:
        void processBlock() {
            uint32_t w[80];
            for (size_t i = 0; i < 16; i++) {
                w[i] = (m_block[i * 4 + 0] << 24);
                w[i] |= (m_block[i * 4 + 1] << 16);
                w[i] |= (m_block[i * 4 + 2] << 8);
                w[i] |= (m_block[i * 4 + 3]);
            }
            for (size_t i = 16; i < 80; i++) {
                w[i] = LeftRotate((w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]), 1);
            }

            uint32_t a = m_digest[0];
            uint32_t b = m_digest[1];
            uint32_t c = m_digest[2];
            uint32_t d = m_digest[3];
            uint32_t e = m_digest[4];

            for (std::size_t i = 0; i < 80; ++i) {
                uint32_t f = 0;
                uint32_t k = 0;

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
                uint32_t temp = LeftRotate(a, 5) + f + e + k + w[i];
                e = d;
                d = c;
                c = LeftRotate(b, 30);
                b = a;
                a = temp;
            }

            m_digest[0] += a;
            m_digest[1] += b;
            m_digest[2] += c;
            m_digest[3] += d;
            m_digest[4] += e;
        }
    private:
        digest32_t m_digest;
        uint8_t m_block[64];
        size_t m_blockByteIndex;
        size_t m_byteCount;
    };
}
#endif








int clz(uint32_t x)
{
    static const char debruijn32[32] = {
        0, 31, 9, 30, 3, 8, 13, 29, 2, 5, 7, 21, 12, 24, 28, 19,
        1, 10, 4, 14, 6, 22, 25, 20, 11, 15, 23, 26, 16, 27, 17, 18
    };
    x |= x >> 1;
    x |= x >> 2;
    x |= x >> 4;
    x |= x >> 8;
    x |= x >> 16;
    x++;
    return debruijn32[x * 0x076be629 >> 27];
}

unsigned int CountLeadingZero(const unsigned int* buffer) {
    unsigned int lastCount = 0;
    unsigned int result = 0;
    unsigned int idx = 0;
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






int main(void) {
    printf("started running\n");

    // Create the two input vectors
    int i;
    const int LIST_SIZE = 1024;
    inbuf* A = (inbuf*)malloc(sizeof(inbuf) * 1);
    for (i = 0; i < 1; i++) {
        //auto aChar = (char*)&A[i].buffer;
        //strcpy_s(aChar, 15, target.data());
        A[i].buffer = 1664974585;

    }

    // Load the kernel source code into the array source_str
    FILE* fp = nullptr;
    char* source_str;
    size_t source_size;

    fopen_s(&fp, "kernel.cpp", "r");
    if (!fp) {
        fprintf(stderr, "Failed to load kernel.\n");
        exit(1);
    }
    source_str = (char*)malloc(MAX_SOURCE_SIZE);
    source_size = fread(source_str, 1, MAX_SOURCE_SIZE, fp);
    fclose(fp);
    printf("kernel loading done\n");
    // Get platform and device information
  // Get platform and device information
  //
  //
  //
    cl_platform_id platform_id = NULL;
    cl_device_id device_id = NULL;
    cl_uint ret_num_devices;
    cl_uint ret_num_platforms;
    cl_int ret = clGetPlatformIDs(1, &platform_id, &ret_num_platforms);
    ret = clGetDeviceIDs(platform_id, CL_DEVICE_TYPE_GPU, 1,
        &device_id, &ret_num_devices);


    printf("ret at %d is %d\n", __LINE__, ret);
    // Create an OpenCL context
    cl_context context = clCreateContext(NULL, 1, &device_id, NULL, NULL, &ret);
    printf("ret at %d is %d\n", __LINE__, ret);

    // Create a command queue
    cl_command_queue command_queue = clCreateCommandQueue(context, device_id, 0, &ret);
    printf("ret at %d is %d\n", __LINE__, ret);

    // Create memory buffers on the device for each vector 
    cl_mem a_mem_obj = clCreateBuffer(context, CL_MEM_READ_ONLY,
        1 * sizeof(inbuf), NULL, &ret);
    cl_mem c_mem_obj = clCreateBuffer(context, CL_MEM_WRITE_ONLY,
        LIST_SIZE * sizeof(outbuf), NULL, &ret);

    // Copy the lists A and B to their respective memory buffers
    ret = clEnqueueWriteBuffer(command_queue, a_mem_obj, CL_TRUE, 0,
        1 * sizeof(inbuf), A, 0, NULL, NULL);
    printf("ret at %d is %d\n", __LINE__, ret);

    printf("before building\n");
    // Create a program from the kernel source
    cl_program program = clCreateProgramWithSource(context, 1,
        (const char**)&source_str, (const size_t*)&source_size, &ret);
    printf("ret at %d is %d\n", __LINE__, ret);

    // Build the program
    ret = clBuildProgram(program, 1, &device_id, "-cl-std=CL2.0 "
#if _DEBUG
        "-D _DEBUG"
#endif 
        , NULL, NULL);
    printf("ret at %d is %d\n", __LINE__, ret);

    char buffer[0x8000];
    size_t bufSize = 0x8000;
    ret = clGetProgramBuildInfo(program, device_id, CL_PROGRAM_BUILD_LOG, bufSize, &buffer, &bufSize);
    printf("ret at %d is %d\n%s\n", __LINE__, ret, buffer);
    
    printf("after building\n");


    printf("prepare hash state\n");
    {
        // Create the OpenCL kernel
        cl_kernel kernel = clCreateKernel(program, "prepareHashStates", &ret);
        printf("ret at %d is %d\n", __LINE__, ret);



        // debug code
        struct SHA1State {

            unsigned int m_digest[5];
            unsigned char m_block[64];
            size_t m_blockByteIndex;
            size_t m_byteCount;
        };

        SHA1State StoredHashState;

        cl_mem hashStateMem = clCreateBuffer(context, CL_MEM_READ_WRITE, 1 * sizeof(StoredHashState), NULL, &ret);
        ret = clSetKernelArg(kernel, 0, sizeof(cl_mem), (void*)&hashStateMem);

        cl_event event = clCreateUserEvent(context, nullptr);
        ret = clEnqueueTask(command_queue, kernel, 0, nullptr, &event);
        clWaitForEvents(1, &event);


        CL_INVALID_VALUE;

        ret = clEnqueueReadBuffer(command_queue, hashStateMem, CL_TRUE, 0,
            1 * sizeof(StoredHashState), &StoredHashState, 0, NULL, &event);
        clWaitForEvents(1, &event);





        clReleaseEvent(event);
        clReleaseKernel(kernel);
        clReleaseMemObject(hashStateMem);
    }

    printf("single hash test\n");
    {
        // Create the OpenCL kernel
        cl_kernel kernel = clCreateKernel(program, "SingleHash", &ret);
        printf("ret at %d is %d\n", __LINE__, ret);



        // debug code
        typedef struct {
            cl_ulong idx;
            unsigned int count;
            char textBuf[180];
            unsigned int buffer[0x5];
        } outbufDebug;

        outbufDebug buf;

        cl_ulong startNumber = 780035720717;
        ret = clSetKernelArg(kernel, 0, sizeof(startNumber), (void*)&startNumber);
        ret = clSetKernelArg(kernel, 1, sizeof(cl_mem), (void*)&c_mem_obj);

        cl_event event = clCreateUserEvent(context, nullptr);
        ret = clEnqueueTask(command_queue, kernel, 0, nullptr, &event);
        clWaitForEvents(1, &event);


        CL_INVALID_VALUE;

        ret = clEnqueueReadBuffer(command_queue, c_mem_obj, CL_TRUE, 0,
            1 * sizeof(buf), &buf, 0, NULL, &event);
        clWaitForEvents(1, &event);

        auto mycount = CountLeadingZero(buf.buffer);

        clReleaseEvent(event);
        clReleaseKernel(kernel);
    }


    printf("general hash test\n");
    {
        // Create the OpenCL kernel
        cl_kernel kernel = clCreateKernel(program, "HashTest", &ret);
        printf("ret at %d is %d\n", __LINE__, ret);

        std::string inputString("MXXpncQ==780035720717");

        cl_mem tempMem = clCreateBuffer(context, CL_MEM_READ_WRITE, inputString.length(), NULL, &ret);
        ret = clEnqueueWriteBuffer(command_queue, tempMem, CL_TRUE, 0, inputString.length(), (const void*)inputString.data(), 0, NULL, NULL);
        // debug code

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

        typedef struct {
            cl_ulong idx;
            unsigned int count;
            char textBuf[180];
            unsigned int buffer[0x10];
            HashState state;
        } outbufDebug;

        outbufDebug buf;

        ret = clSetKernelArg(kernel, 0, sizeof(cl_mem), (void*)&tempMem);
        cl_ulong stringLength = inputString.length();
        ret = clSetKernelArg(kernel, 1, sizeof(stringLength), (void*)&stringLength);
        ret = clSetKernelArg(kernel, 2, sizeof(cl_mem), (void*)&c_mem_obj);

        cl_event event = clCreateUserEvent(context, nullptr);
        ret = clEnqueueTask(command_queue, kernel, 0, nullptr, &event);
        clWaitForEvents(1, &event);


        CL_INVALID_VALUE;

        ret = clEnqueueReadBuffer(command_queue, c_mem_obj, CL_TRUE, 0,
            1 * sizeof(buf), &buf, 0, NULL, &event);
        clWaitForEvents(1, &event);

        auto test1 = (unsigned int)rotate((unsigned int)0x12345678, 5);
        auto test2 = (unsigned int)rotate((unsigned int)0x12345678, 30);
        auto test3 = (unsigned int)rotate((unsigned int)0x67452301, 5);


        sha1::SHA1 s;
        s.processBytes(inputString.c_str(), inputString.size());
        uint32_t digest[5];
        s.getDigest(digest);
        char tmp[48];
        snprintf(tmp, 45, "%08x %08x %08x %08x %08x", digest[0], digest[1], digest[2], digest[3], digest[4]);



        clReleaseEvent(event);
        clReleaseKernel(kernel);

        clReleaseMemObject(tempMem);
    }


    printf("prepare main kernel\n");

    // Create the OpenCL kernel
    cl_kernel kernel = clCreateKernel(program, "hash_main", &ret);
    printf("ret at %d is %d\n", __LINE__, ret);

    // Set the arguments of the kernel
    ret = clSetKernelArg(kernel, 0, sizeof(cl_mem), (void*)&a_mem_obj);
    printf("ret at %d is %d\n", __LINE__, ret);

    ret = clSetKernelArg(kernel, 1, sizeof(cl_mem), (void*)&c_mem_obj);
    printf("ret at %d is %d\n", __LINE__, ret);

    //added this to fix garbage output problem
    //ret = clSetKernelArg(kernel, 3, sizeof(int), &LIST_SIZE);

    printf("before execution\n");
    // Execute the OpenCL kernel on the list


    // FOUND! 41 - 783199680361

    //uint64_t startOffset = 1118701419075ull; //
    uint64_t startOffset = 783199680360ull;
    uint8_t currentRecord = 37;
    //uint64_t startOffset =   540965468048ull;
    //uint64_t startOffset = 4284284665ull;
    A->buffer = startOffset;
    uint64_t endOffset = 0xfffffffffffull;
    uint64_t distanceToEnd = endOffset - startOffset;

    size_t global_item_size = distanceToEnd;
    size_t local_item_size = 1024; // Divide work items into groups of 64

    struct exitBuf {
        outbuf x[1024];
    };

    exitBuf* C = (exitBuf*)malloc(sizeof(outbuf) * LIST_SIZE);

    auto start = std::chrono::high_resolution_clock::now();


    size_t maxPerBlock = 10000000;
    size_t numberOfBlocks = global_item_size / maxPerBlock;
    auto steps = global_item_size / numberOfBlocks;
    steps -= steps % 8192ull;

    cl_event event = clCreateUserEvent(context, nullptr);
    int zer = 0;
    clEnqueueFillBuffer(command_queue, c_mem_obj, &zer, 1,
        0, sizeof(outbuf)* LIST_SIZE, 0, nullptr, &event);
    clWaitForEvents(1, &event);


    for (int i = 0; i < numberOfBlocks; ++i) {

        ret = clEnqueueWriteBuffer(command_queue, a_mem_obj, CL_TRUE, 0,
            1 * sizeof(inbuf), A, 0, NULL, NULL);
        //printf("ret at %d is %d\n", __LINE__, ret);
        A->buffer += steps;
        //printf("doing %llu\nto    %llu  %f\n", A->buffer, A->buffer + steps, static_cast<double>(A->buffer - startOffset) / endOffset);
        ret = clEnqueueNDRangeKernel(command_queue, kernel, 1, NULL,
            &steps, &local_item_size, 0, NULL, NULL);


        auto end = std::chrono::high_resolution_clock::now();
        auto distance = A->buffer - startOffset;
        auto millisecondsElapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        if (millisecondsElapsed > 0)
        //printf("%llu %llu KH/s\n", distance, (distance / millisecondsElapsed)*1000 );

        if (i % 256 == 0) {
            printf("%f at %llu\n", static_cast<double>(A->buffer - startOffset) / endOffset, A->buffer);

            ret = clEnqueueReadBuffer(command_queue, c_mem_obj, CL_TRUE, 0,
                LIST_SIZE * sizeof(outbuf), C, 0, NULL, &event);
            clWaitForEvents(1, &event);

            for (auto& it : C->x) {
                if (it.idx == 0) break;

                printf("FOUND! %u - %llu\n", it.count, it.idx);
                if (it.count == currentRecord)
                    printf("Alt Record! %u - %llu\n", it.count, it.idx);
                if (it.count > currentRecord) {
                    printf("NEW RECORD!!!!!!!!!!!!!!!!!! %u - %llu\n", it.count, it.idx);
                    currentRecord = it.count;
                }
                    
            }
            clEnqueueFillBuffer(command_queue, c_mem_obj, &zer, 1,
                0, sizeof(outbuf)* LIST_SIZE, 0, nullptr, &event);
            ret = clEnqueueReadBuffer(command_queue, c_mem_obj, CL_TRUE, 0,
                LIST_SIZE * sizeof(outbuf), C, 0, NULL, NULL);
        }

    }

    printf("after execution\n");
    // Read the memory buffer C on the device to the local variable C

    ret = clEnqueueReadBuffer(command_queue, c_mem_obj, CL_TRUE, 0,
        LIST_SIZE * sizeof(outbuf), C, 0, NULL, NULL);
    printf("after copying\n");
    // Display the result to the screen
    //for (i = 0; i < LIST_SIZE; i++) {
        //auto outBufferChar = (char*)&C[i].buffer;
        //printf("%s = ", (char*)&A[i].buffer);
        //for (int i = 0; i < strlen(outBufferChar); i++) {
        //    printf(" %02x", outBufferChar[i]);
        //}
        //printf("\n");
    //}

    auto end = std::chrono::high_resolution_clock::now();
    printf("%f hashes per sec in %ull ms",
        static_cast<double>(global_item_size) / std::chrono::duration_cast<std::chrono::seconds>(end - start).count(),
        (uint64_t)std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count()
    );



    // Clean up
    ret = clFlush(command_queue);
    ret = clFinish(command_queue);
    ret = clReleaseKernel(kernel);
    ret = clReleaseProgram(program);
    ret = clReleaseMemObject(a_mem_obj);
    ret = clReleaseMemObject(c_mem_obj);
    ret = clReleaseCommandQueue(command_queue);
    ret = clReleaseContext(context);
    free(A);
    free(C);
    return 0;
}