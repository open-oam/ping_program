#ifndef __BPF_HELPERS_H
#define __BPF_HELPERS_H

#define SEC(NAME) __attribute__((section(NAME), used))

#define INLINE __attribute__((__always_inline__))

#ifndef __U32_TYPE
typedef unsigned long __u32;

#endif

struct bpf_map_def {
  __u32 map_type;
  __u32 key_size;
  __u32 value_size;
  __u32 max_entries;
  __u32 map_flags;
  // Array/Hash of maps use case: pointer to inner map template
//   void *inner_map_def;
  // Define this to make map system wide ("object pinning")
  // path could be anything, like '/sys/fs/bpf/foo'
  // WARN: You must have BPF filesystem mounted on provided location
//   const char *persistent_path;
};

#endif