#ifndef _IMA_HASH_H
#define _IMA_HASH_H

#define FILE_HASH_MASK 0x80000000

typedef struct ima_hash {
    u8 digest[32];
} ima_hash_t, *ima_hash_t_p;

// ima hash map
struct ima_hash_map
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u32);
    __type(value, ima_hash_t);
    __uint(max_entries, 10240);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
}kubearmor_ima_hash_map SEC(".maps");

#endif // _IMA_HASH_H

