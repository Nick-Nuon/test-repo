// #define _GNU_SOURCE
// #include <linux/perf_event.h>
// #include <sys/syscall.h>
// #include <sys/ioctl.h>
// #include <unistd.h>
// #include <string.h>
// #include <stdio.h>
// #include <stdlib.h>
// #include <stdint.h>
// #include <time.h>
// #include <errno.h>
// #include <stdatomic.h>

// #include <sys/stat.h>
// #include <sys/types.h>
// #include <unistd.h>

// #include <stdio.h>
// #include <stdlib.h>
// #include <string.h>
// #include <dirent.h>
// #include <sys/stat.h>


// #define MIN_REPEATS 5
// #define MIN_TIME_NS 1000000000  // 1 second
// #define MAX_REPEATS 1000000
// #define WARMUP_RUNS 2

// #define MAX_FILES 1024

// typedef struct {
//     char *filename;
//     unsigned char *content;
//     size_t size;
// } FileData;

// // Loads all regular files from a directory into memory.
// int load_files_from_dir(const char *dirpath, FileData *files, size_t *file_count) {
//     DIR *dir = opendir(dirpath);
//     if (!dir) {
//         perror("opendir");
//         return 0;
//     }

//     struct dirent *entry;
//     size_t count = 0;

//     while ((entry = readdir(dir)) != NULL) {
//         // Skip . and ..
//         if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
//             continue;

//         if (count >= MAX_FILES) {
//             fprintf(stderr, "Too many files in directory.\n");
//             break;
//         }

//         char fullpath[4096];
//         snprintf(fullpath, sizeof(fullpath), "%s/%s", dirpath, entry->d_name);

//         struct stat st;
//         if (stat(fullpath, &st) != 0 || !S_ISREG(st.st_mode)) {
//             continue; // Skip if not a regular file
//         }

//         FILE *f = fopen(fullpath, "rb");
//         if (!f) {
//             perror("fopen");
//             continue;
//         }

//         unsigned char *buf = malloc(st.st_size);
//         if (!buf) {
//             perror("malloc");
//             fclose(f);
//             continue;
//         }

//         size_t read = fread(buf, 1, st.st_size, f);
//         fclose(f);

//         if (read != st.st_size) {
//             fprintf(stderr, "Warning: incomplete read of %s\n", fullpath);
//             free(buf);
//             continue;
//         }

//         files[count].filename = strdup(entry->d_name);
//         files[count].content = buf;
//         files[count].size = st.st_size;
//         count++;
//     }

//     closedir(dir);
//     *file_count = count;
//     return 1;
// }

// /**
//  * Returns the size of a file in bytes given its path.
//  * Returns -1 on failure.
//  */
// off_t get_file_size(const char *path) {
//     FILE *f = fopen(path, "rb");
//     if (!f) {
//       perror("fopen");
//       return -1;
//     }
  
//     int fd = fileno(f);
//     struct stat st;
//     if (fstat(fd, &st) == -1) {
//       perror("fstat");
//       fclose(f);
//       return -1;
//     }
  
//     fclose(f);
//     return st.st_size;
//   }
  

// static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
//                             int cpu, int group_fd, unsigned long flags) {
//     return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
// }

// double elapsed_seconds(struct timespec start, struct timespec end) {
//     return (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
// }

// uint64_t elapsed_nanoseconds(struct timespec start, struct timespec end) {
//     return (end.tv_sec - start.tv_sec) * 1000000000ULL + (end.tv_nsec - start.tv_nsec);
// }

// int main() {
//     // Setup perf_event_attr for CPU cycles (group leader)
//     struct perf_event_attr pe_cycles;
//     memset(&pe_cycles, 0, sizeof(struct perf_event_attr));
//     pe_cycles.type = PERF_TYPE_HARDWARE;
//     pe_cycles.size = sizeof(struct perf_event_attr);
//     pe_cycles.config = PERF_COUNT_HW_CPU_CYCLES;
//     pe_cycles.disabled = 1;
//     pe_cycles.exclude_kernel = 1;
//     pe_cycles.exclude_hv = 1;
//     pe_cycles.read_format = PERF_FORMAT_GROUP;

//     int fd_cycles = perf_event_open(&pe_cycles, 0, -1, -1, 0);
//     if (fd_cycles == -1) {
//         perror("perf_event_open (cycles)");
//         return 1;
//     }

//     struct perf_event_attr pe_instr = pe_cycles;
//     pe_instr.config = PERF_COUNT_HW_INSTRUCTIONS;
//     int fd_instr = perf_event_open(&pe_instr, 0, -1, fd_cycles, 0);
//     if (fd_instr == -1) {
//         perror("perf_event_open (instructions)");
//         return 1;
//     }

//     FileData swedenzone[MAX_FILES];
//     FileData enron[MAX_FILES];
//     size_t enron_file_count = 0;

//     const char *enronpath = "util/data/email"; // change to "data/dns" if needed

//     if (!load_files_from_dir(enronpath, enron, &enron_file_count)) {
//         fprintf(stderr, "Failed to load enron files.\n");
//         return 1;
//     }

//     size_t sweden_file_count = 1;
//     const char *swedenpath = "util/data/dns"; 

//     if (!load_files_from_dir(swedenpath, swedenzone, &sweden_file_count)) {
//         fprintf(stderr, "Failed to load sweden files.\n");
//         return 1;
//     }



//     uint64_t total_cycles = 0;
//     uint64_t total_instructions = 0;
//     uint64_t total_elapsed_ns = 0;
//     uint64_t values[3];
//     size_t N = MIN_REPEATS;
//     if (N == 0) N = 1;

//     for (size_t i = 0; i < N; i++) {
//         struct timespec start_time, end_time;
//         atomic_thread_fence(memory_order_acquire);
//         clock_gettime(CLOCK_MONOTONIC, &start_time);

//         ioctl(fd_cycles, PERF_EVENT_IOC_RESET, PERF_IOC_FLAG_GROUP);
//         ioctl(fd_cycles, PERF_EVENT_IOC_ENABLE, PERF_IOC_FLAG_GROUP);

//         // === CODE TO BENCHMARK ===
//         volatile int sum = 0;
//         for (int j = 0; j < 1000000; j++) {
//             sum += j;
//         }
//         // ==========================

//         ioctl(fd_cycles, PERF_EVENT_IOC_DISABLE, PERF_IOC_FLAG_GROUP);
//         atomic_thread_fence(memory_order_release);
//         clock_gettime(CLOCK_MONOTONIC, &end_time);

//         if (read(fd_cycles, values, sizeof(values)) == -1) {
//             perror("read (perf group)");
//             return 1;
//         }

//         if (i >= WARMUP_RUNS) {
//             total_cycles += values[1];
//             total_instructions += values[2];
//             total_elapsed_ns += elapsed_nanoseconds(start_time, end_time);
//         }

//         // If last run and runtime is too short, increase N
//         if ((i + 1 == N) && (total_elapsed_ns < MIN_TIME_NS) && (N < MAX_REPEATS)) {
//             N *= 10;
//         }
//     }

//     size_t effective_runs = N > WARMUP_RUNS ? (N - WARMUP_RUNS) : 1;
//     double elapsed_sec = total_elapsed_ns / 1e9;
//     double ipc = total_cycles > 0 ? ((double)total_instructions / total_cycles) : 0.0;

//     printf("Benchmark ran %zu iterations (%zu used after warmup)\n", N, effective_runs);
//     printf("Total elapsed (wall):     %.6f s\n", elapsed_sec);
//     printf("CPU cycles (avg):         %llu\n", (unsigned long long)(total_cycles / effective_runs));
//     printf("Instructions (avg):       %llu\n", (unsigned long long)(total_instructions / effective_runs));
//     printf("Instructions per cycle:   %.4f\n", ipc);

//     for (size_t i = 0; i < enron_file_count; i++) {
//         printf("File: %s (%zu bytes)\n", enron[i].filename, enron[i].size);
//         // Do encoding work here with files[i].content
//         free(enron[i].content);
//         free(enron[i].filename);
//     }

//         // for (size_t i = 0; i < file_count; i++) {
//     //     printf("File: %s (%zu bytes)\n", files[i].filename, files[i].size);
//     //     // Do encoding work here with files[i].content
//     //     free(files[i].content);
//     //     free(files[i].filename);
//     // }


//     close(fd_instr);
//     close(fd_cycles);
//     return 0;
// }


// // #define MAX_FILES 1024

// // typedef struct {
// //     char *filename;
// //     unsigned char *content;
// //     size_t size;
// // } FileData;

// // // Loads all regular files from a directory into memory.
// // int load_files_from_dir(const char *dirpath, FileData *files, size_t *file_count) {
// //     DIR *dir = opendir(dirpath);
// //     if (!dir) {
// //         perror("opendir");
// //         return 0;
// //     }

// //     struct dirent *entry;
// //     size_t count = 0;

// //     while ((entry = readdir(dir)) != NULL) {
// //         // Skip . and ..
// //         if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
// //             continue;

// //         if (count >= MAX_FILES) {
// //             fprintf(stderr, "Too many files in directory.\n");
// //             break;
// //         }

// //         char fullpath[4096];
// //         snprintf(fullpath, sizeof(fullpath), "%s/%s", dirpath, entry->d_name);

// //         struct stat st;
// //         if (stat(fullpath, &st) != 0 || !S_ISREG(st.st_mode)) {
// //             continue; // Skip if not a regular file
// //         }

// //         FILE *f = fopen(fullpath, "rb");
// //         if (!f) {
// //             perror("fopen");
// //             continue;
// //         }

// //         unsigned char *buf = malloc(st.st_size);
// //         if (!buf) {
// //             perror("malloc");
// //             fclose(f);
// //             continue;
// //         }

// //         size_t read = fread(buf, 1, st.st_size, f);
// //         fclose(f);

// //         if (read != st.st_size) {
// //             fprintf(stderr, "Warning: incomplete read of %s\n", fullpath);
// //             free(buf);
// //             continue;
// //         }

// //         files[count].filename = strdup(entry->d_name);
// //         files[count].content = buf;
// //         files[count].size = st.st_size;
// //         count++;
// //     }

// //     closedir(dir);
// //     *file_count = count;
// //     return 1;
// // }

// // int main() {
// //     FileData files[MAX_FILES];
// //     size_t file_count = 0;
// //     char cwd[1024];
// //     getcwd(cwd, sizeof(cwd));
// //     printf("Current working directory: %s\n", cwd);


// //     const char *dirpath = "data/email"; // change to "data/dns" if needed

// //     if (!load_files_from_dir(dirpath, files, &file_count)) {
// //         fprintf(stderr, "Failed to load files from directory.\n");
// //         return 1;
// //     }

// //     for (size_t i = 0; i < file_count; i++) {
// //         printf("File: %s (%zu bytes)\n", files[i].filename, files[i].size);
// //         // Do encoding work here with files[i].content
// //         free(files[i].content);
// //         free(files[i].filename);
// //     }

// //     return 0;
// // }


#define _GNU_SOURCE
#include <linux/perf_event.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <errno.h>
#include <stdatomic.h>
#include <sys/stat.h>
#include <dirent.h>

#define MIN_REPEATS 5
#define MIN_TIME_NS 1000000000ULL  // 1 second
#define MAX_REPEATS 1000000
#define WARMUP_RUNS 2
#define MAX_FILES 1024

typedef struct {
    char *filename;
    unsigned char *content;
    size_t size;
    size_t encoded_size;
    unsigned char *encoded;
} FileData;

static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
                            int cpu, int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

double elapsed_seconds(struct timespec start, struct timespec end) {
    return (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
}

uint64_t elapsed_nanoseconds(struct timespec start, struct timespec end) {
    return (end.tv_sec - start.tv_sec) * 1000000000ULL + (end.tv_nsec - start.tv_nsec);
}

int load_files_from_dir(const char *dirpath, FileData *files, size_t *file_count) {
    DIR *dir = opendir(dirpath);
    if (!dir) {
        perror("opendir");
        return 0;
    }

    struct dirent *entry;
    size_t count = 0;

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        if (count >= MAX_FILES) {
            fprintf(stderr, "Too many files in directory.\n");
            break;
        }

        char fullpath[4096];
        snprintf(fullpath, sizeof(fullpath), "%s/%s", dirpath, entry->d_name);

        struct stat st;
        if (stat(fullpath, &st) != 0 || !S_ISREG(st.st_mode)) {
            continue;
        }

        FILE *f = fopen(fullpath, "rb");
        if (!f) {
            perror("fopen");
            continue;
        }

        unsigned char *buf = malloc(st.st_size);
        unsigned char *encoded_buf = malloc(((st.st_size + 2) / 3) * 4); // Space for base64 encoded output
        if (!buf || !encoded_buf) {
            perror("malloc");
            free(buf); // Free buf if it was allocated successfully
            free(encoded_buf); // Free encoded_buf if it was allocated successfully
            fclose(f);
            continue;
        }


        size_t read = fread(buf, 1, st.st_size, f);
        fclose(f);

        if (read != st.st_size) {
            fprintf(stderr, "Warning: incomplete read of %s\n", fullpath);
            free(buf);
            continue;
        }

        files[count].filename = strdup(entry->d_name);
        files[count].content = buf;
        files[count].size = st.st_size;
        files[count].encoded_size = ((st.st_size + 2) / 3) * 4; // Base64 encoded size calculation
        files[count].encoded = encoded_buf;
        count++;
    }

    closedir(dir);
    *file_count = count;
    return 1;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <directory>\n", argv[0]);
        return 1;
    }

    const char *dirpath = argv[1];
    FileData files[MAX_FILES];
    size_t file_count = 0;

    if (!load_files_from_dir(dirpath, files, &file_count)) {
        fprintf(stderr, "Failed to load files.\n");
        return 1;
    }

    struct perf_event_attr pe_cycles;
    memset(&pe_cycles, 0, sizeof(pe_cycles));
    pe_cycles.type = PERF_TYPE_HARDWARE;
    pe_cycles.size = sizeof(pe_cycles);
    pe_cycles.config = PERF_COUNT_HW_CPU_CYCLES;
    pe_cycles.disabled = 1;
    pe_cycles.exclude_kernel = 1;
    pe_cycles.exclude_hv = 1;
    pe_cycles.read_format = PERF_FORMAT_GROUP;

    int fd_cycles = perf_event_open(&pe_cycles, 0, -1, -1, 0);
    if (fd_cycles == -1) {
        perror("perf_event_open (cycles)");
        return 1;
    }

    struct perf_event_attr pe_instr = pe_cycles;
    pe_instr.config = PERF_COUNT_HW_INSTRUCTIONS;
    int fd_instr = perf_event_open(&pe_instr, 0, -1, fd_cycles, 0);
    if (fd_instr == -1) {
        perror("perf_event_open (instructions)");
        return 1;
    }

    uint64_t total_cycles = 0, total_instructions = 0, total_elapsed_ns = 0;
    size_t N = MIN_REPEATS;
    if (N == 0) N = 1;

    for (size_t i = 0; i < N; i++) {
        struct timespec start_time, end_time;
        atomic_thread_fence(memory_order_acquire);
        clock_gettime(CLOCK_MONOTONIC, &start_time);

        ioctl(fd_cycles, PERF_EVENT_IOC_RESET, PERF_IOC_FLAG_GROUP);
        ioctl(fd_cycles, PERF_EVENT_IOC_ENABLE, PERF_IOC_FLAG_GROUP);

        // === CODE TO BENCHMARK ===
        // TODO:Here I want to benmark EvP_EncodeUpdate and Evp_EncodeFinal on all the files
        for (size_t f = 0; f < file_count; f++) {
            volatile size_t sum = 0;
            for (size_t j = 0; j < files[f].size; j++) {
                sum += files[f].content[j];
            }
        }
        // ==========================

        ioctl(fd_cycles, PERF_EVENT_IOC_DISABLE, PERF_IOC_FLAG_GROUP);
        atomic_thread_fence(memory_order_release);
        clock_gettime(CLOCK_MONOTONIC, &end_time);

        uint64_t values[3];
        if (read(fd_cycles, values, sizeof(values)) == -1) {
            perror("read (perf group)");
            return 1;
        }

        if (i >= WARMUP_RUNS) {
            total_cycles += values[1];
            total_instructions += values[2];
            total_elapsed_ns += elapsed_nanoseconds(start_time, end_time);
        }

        // If last run and runtime is too short, increase N
        if ((i + 1 == N) && (total_elapsed_ns < MIN_TIME_NS) && (N < MAX_REPEATS)) {
            N *= 10;
        }
    }

    size_t effective_runs = N > WARMUP_RUNS ? (N - WARMUP_RUNS) : 1;
    double elapsed_sec = total_elapsed_ns / 1e9;
    double ipc = total_cycles > 0 ? ((double)total_instructions / total_cycles) : 0.0;

    printf("Benchmark ran %zu iterations (%zu used after warmup)\n", N, effective_runs);
    printf("Total elapsed (wall):     %.6f s\n", elapsed_sec);
    printf("CPU cycles (avg):         %llu\n", (unsigned long long)(total_cycles / effective_runs));
    printf("Instructions (avg):       %llu\n", (unsigned long long)(total_instructions / effective_runs));
    printf("Instructions per cycle:   %.4f\n", ipc);

    printf("\n\nProcessed files:\n");

    for (size_t i = 0; i < file_count; i++) {
        printf("File: %s (%zu bytes)\n", files[i].filename, files[i].size);
        free(files[i].content);
        free(files[i].filename);
    }

    close(fd_instr);
    close(fd_cycles);
    return 0;
}
