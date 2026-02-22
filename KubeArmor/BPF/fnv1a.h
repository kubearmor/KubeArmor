#ifndef _FNV_1A_H
#define _FNV_1A_H

#define FNV_OFFSET_BASIS_64 0xcbf29ce484222325ULL
#define FNV_PRIME_64 0x100000001b3ULL

static __attribute__((noinline)) u64 fnv1a_hash64(const void *data, u32 len, u64 hash)
{
    if (hash == 0)
    {
        hash = FNV_OFFSET_BASIS_64;
    }

    const unsigned char *p = data;

#pragma unroll
    for (int i = 0; i < 256; i++)
    {
        if (i >= len)
        {
            break;
        }
        hash ^= (u64)p[i];
        hash *= FNV_PRIME_64;
    }

    return hash;
}

static __attribute__((noinline)) u64 fnv1a_hash64_str(const char *s, u32 max_len, u64 hash)
{
#pragma unroll
    for (int i = 0; i < max_len; i++)
    {
        char c = s[i];
        if (c == '\0')
        {
            break;
        }
        hash ^= (u64)c;
        hash *= FNV_PRIME_64;
    }
    return hash;
}

#endif // _FNV_1A_H
