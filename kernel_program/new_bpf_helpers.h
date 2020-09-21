#ifndef __BPF_HELPERS_H
#define __BPF_HELPERS_H

// ELF File macros
#define SEC(NAME) __attribute__ ((section(NAME), used))
#define INLINE __attribute__((__always_inline__))

// Offset macros





// Types used in large amount of code
typedef unsigned short      __u8;
typedef unsigned            __u16;
typedef unsigned long       __u32;
typedef unsigned long long  __u64;

// BPF map struct definition
struct bpf_map_def {
    __u32 map_type;
    __u32 key_size;
    __u32 value_size;
    __u32 max_entries;
    __u32 map_flags;
};

#endif //__BPF_HELPERS_H