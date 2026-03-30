#ifndef _FNV_1A_H
#define _FNV_1A_H

/* suppress clangd errors */
#ifdef __clang__

typedef unsigned char  u8;
typedef unsigned int   u32;
typedef unsigned long long u64;
typedef long long s64;

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

#endif

#define FNV_OFFSET_BASIS_64 0xcbf29ce484222325ULL
#define FNV_PRIME_64 0x100000001b3ULL

static __always_inline u64 fnv1a_hash_u8(u8 v, u64 hash)
{
    if (hash == 0)
    {
        hash = FNV_OFFSET_BASIS_64;
    }
    hash ^= (u64)v;
    hash *= FNV_PRIME_64;
    return hash;
}

static __always_inline u64 fnv1a_hash_u32(u32 v, u64 hash)
{
    hash = fnv1a_hash_u8((u8)(v), hash);
    hash = fnv1a_hash_u8((u8)(v >> 8), hash);
    hash = fnv1a_hash_u8((u8)(v >> 16), hash);
    hash = fnv1a_hash_u8((u8)(v >> 24), hash);
    return hash;
}

static __always_inline u64 fnv1a_hash_u64(u64 v, u64 hash)
{
    hash = fnv1a_hash_u8((u8)(v), hash);
    hash = fnv1a_hash_u8((u8)(v >> 8), hash);
    hash = fnv1a_hash_u8((u8)(v >> 16), hash);
    hash = fnv1a_hash_u8((u8)(v >> 24), hash);
    hash = fnv1a_hash_u8((u8)(v >> 32), hash);
    hash = fnv1a_hash_u8((u8)(v >> 40), hash);
    hash = fnv1a_hash_u8((u8)(v >> 48), hash);
    hash = fnv1a_hash_u8((u8)(v >> 56), hash);
    return hash;
}

static __always_inline u64 fnv1a_hash_s64(s64 v, u64 hash)
{
    return fnv1a_hash_u64((u64)v, hash);
}

// keep this helper for cases where the input is not a scalar, use
// fnv1a_hash_u8/u32/u64 otherwise to avoid large unrolled loops.
static __always_inline u64 fnv1a_hash64(const void *data, u32 len, u64 hash)
{
    const unsigned char *p = data;

#pragma unroll
    for (int i = 0; i < 256; i++)
    {
        if (i >= len)
        {
            break;
        }

        hash = fnv1a_hash_u8(p[i], hash);
    }

    return hash;
}

static __always_inline u64 fnv1a_hash64_str(const char *s, u32 max_len, u64 hash)
{
#pragma unroll
    for (int i = 0; i < 256; i++)
    {
        if (i >= max_len)
        {
            break;
        }

        char c = s[i];
        if (c == '\0')
        {
            break;
        }

        hash = fnv1a_hash_u8((u8)c, hash);
    }

    return hash;
}

#endif // _FNV_1A_H
