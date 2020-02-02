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
    ret = clBuildProgram(program, 1, &device_id, NULL, NULL, NULL);
    printf("ret at %d is %d\n", __LINE__, ret);

    char buffer[0x2000];
    size_t bufSize = 0x2000;
    ret = clGetProgramBuildInfo(program, device_id, CL_PROGRAM_BUILD_LOG, bufSize, &buffer, &bufSize);
    printf("ret at %d is %d\n", __LINE__, ret);
    
    printf("after building\n");
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

    uint64_t startOffset =   47160063888ull;
    //uint64_t startOffset = 4284284665ull;
    A->buffer = startOffset;
    uint64_t endOffset = 0xfffffffffull;
    uint64_t distanceToEnd = endOffset - startOffset;

    uint64_t x64Steps = distanceToEnd / 128ull;
    x64Steps -= x64Steps % 8192ull;
    size_t global_item_size = 128ull * x64Steps; // Process the entire lists
    
    size_t local_item_size = 128; // Divide work items into groups of 64








    struct exitBuf {
        outbuf x[1024];
    };

    exitBuf* C = (exitBuf*)malloc(sizeof(outbuf) * LIST_SIZE);

    auto start = std::chrono::high_resolution_clock::now();


    for (int i = 0; i < 4096; ++i) {
        auto steps = global_item_size / 4096;

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

            int zer = 0;

            ret = clEnqueueReadBuffer(command_queue, c_mem_obj, CL_TRUE, 0,
                LIST_SIZE * sizeof(outbuf), C, 0, NULL, NULL);

            for (auto& it : C->x) {
                if (it.idx == 0) break;

                printf("FOUND! %u - %llu\n", it.count, it.idx);
            }
            clEnqueueFillBuffer(command_queue, c_mem_obj, &zer, 1,
                0, sizeof(outbuf)* LIST_SIZE, 0, nullptr, nullptr);
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
    printf("%f hashes per sec",
        static_cast<double>(global_item_size) / std::chrono::duration_cast<std::chrono::seconds>(end - start).count()
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