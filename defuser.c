#include "defuser.h"
#include <string.h>
#include <inttypes.h>
#include <stdio.h>

#define MAX_FIELDS 8

/*
 * 把 values 中的 count 个整数写成一行“空格分隔的无符号十进制整数”，存入 out。
 * 成功返回 0；count 为 0（还没有实现）、snprintf 出错或结果被截断时返回非零。
 */
static int write_answer(char *out, size_t cap, const uint32_t *values, size_t count) {
    size_t used = 0;
    for (size_t i = 0; i < count; ++i) {
        int size = snprintf(out + used, cap - used, "%s%" PRIu32, i ? " " : "", values[i]);
        if (size < 0 || (size_t)size >= cap - used) return 1;
        used += (size_t)size;
    }
    return count == 0;
}


int solve_phase_1(uint64_t challenge, char *out, size_t cap) {
    uint32_t values[MAX_FIELDS] = {0};

    uint32_t H = (uint32_t)(challenge >> 32);
    uint32_t M = (uint32_t)(challenge >> 16);
    uint32_t L = (uint32_t)challenge;

    uint32_t A = (uint32_t)(5u * H + M) ^ 0x18dfu;
    uint32_t B = (uint32_t)(5u * (L - H) + 0x8223u);
    uint32_t R = (uint32_t)(5u * B) ^ (A + 0x88bcu);

    values[0] = R;
    return write_answer(out, cap, values, 1);
}



int solve_phase_2(uint64_t challenge, char *out, size_t cap) {
    uint32_t values[MAX_FIELDS] = {0};

    values[0] = 20u + 2u * (uint32_t)((challenge >> 31) & 0xfu);

    for (uint32_t i = 1; i < 6; ++i) {
        uint32_t shift = 22u + 5u * (i - 1u);
        uint32_t nibble = (uint32_t)(challenge >> shift) & 0xfu;
        uint32_t t = (nibble + i) ^ values[i - 1];
        values[i] = 3u * t;
    }

    return write_answer(out, cap, values, 6);
}



int solve_phase_3(uint64_t challenge, char *out, size_t cap) {
    uint32_t values[MAX_FIELDS] = {0};

    uint32_t x = (uint32_t)(challenge & 7u);

    uint32_t k = (uint32_t)(challenge >> 3)
               ^ (uint32_t)(challenge >> 32);

    uint32_t y = 0;

    switch (x) {
        case 0:
            y = (2u * k) ^ 0xa287u;
            break;
        case 1:
            y = 3u * k + 0xa70du;
            break;
        case 2:
            y = (k ^ 0x346u) + (k >> 1);
            break;
        case 3:
            y = 5u * k + 0x2fc0bu;
            break;
        case 4:
            y = (k ^ 0x189cu) + (k >> 2);
            break;
        case 5:
            y = (2u * k) ^ 0x737du;
            break;
        case 6:
            y = 5u * k + 0xdf66u;
            break;
        case 7:
            y = 3u * k + 0x112cu;
            break;
    }

    values[0] = x;
    values[1] = y;

    return write_answer(out, cap, values, 2);
}


static uint32_t p4_compute(uint32_t a, uint32_t b,
                           uint32_t c, uint32_t d) {
    uint32_t m = b + (c - b) / 2u;

    if (a == m) {
        return (m + 0xd6u) ^ d;
    }

    uint32_t t;

    if (a < m) {
        t = p4_compute(a, b, m - 1u, d);
        return (3u * t ^ (m + d)) ^ 0x13u;
    } else {
        t = p4_compute(a, m + 1u, c, d);
        return (3u * t ^ (m + d)) ^ 0x16u;
    }
}

int solve_phase_4(uint64_t challenge, char *out, size_t cap) {
    uint32_t values[MAX_FIELDS] = {0};

    uint32_t a = (uint32_t)challenge & 0x7fu;
    uint32_t d = (uint32_t)(challenge >> 7)
               ^ (uint32_t)(challenge >> 32);

    values[0] = p4_compute(a, 0u, 127u, d);

    return write_answer(out, cap, values, 1);
}



static uint32_t p5_compute(uint64_t challenge, uint32_t *last_tag) {
    static const uint32_t node_value[12] = {
        16315, 29470, 23152, 38726,
        15944, 31985, 37551, 29109,
        62349, 37085, 49171, 52872
    };

    static const uint32_t node_tag[12] = {
        801, 2614, 111, 1624,
        1838, 1392, 371, 2353,
        520, 1098, 2091, 2937
    };

    static const uint32_t node_next[12] = {
        2, 8, 1, 7,
        0, 9, 10, 0,
        11, 6, 3, 5
    };

    static const uint32_t start[8] = {
        4, 0, 2, 1, 8, 11, 5, 9
    };

    uint32_t s = (uint32_t)challenge & 7u;
    uint32_t q = (uint32_t)(challenge >> 3);
    uint32_t h = (uint32_t)(challenge >> 6)
               ^ (uint32_t)(challenge >> 32);

    uint32_t index = start[s];

    uint32_t result = 5u * ((h ^ 0xa252u) + node_value[index])
                    ^ node_tag[index];

    *last_tag = node_tag[index];

    uint32_t count = q & 3u;

    for (uint32_t i = 0; i < count; ++i) {
        index = node_next[index];

        result = 5u * (result + node_value[index])
               ^ node_tag[index];

        *last_tag = node_tag[index];
    }

    return result;
}

int solve_phase_5(uint64_t challenge, char *out, size_t cap) {
    uint32_t values[MAX_FIELDS] = {0};

    values[0] = p5_compute(challenge, &values[1]);

    return write_answer(out, cap, values, 2);
}

static uint32_t p6_op(uint32_t op, uint32_t x) {
    switch (op) {
        case 0: return (x ^ (x >> 5)) + 0xab9bu;
        case 1: return (x >> 2) | (x << 30);
        case 2: return ((x << 7) | (x >> 25)) ^ 0xf19fu;
        case 3: return ((x << 7) + 0x44d8u) ^ (3u * x);
        case 4: return (x ^ 0x444du) + (x << 7);
        case 5: return (x + 0xa303u) ^ (x >> 7);
        default: return 0;
    }
}

static uint32_t p6_table(uint32_t index, uint32_t x) {
    static const uint32_t mapping[8] = {
        3, 5, 4, 2, 1, 0, 4, 3
    };
    return p6_op(mapping[index & 7u], x);
}
int solve_phase_6(uint64_t challenge, char *out, size_t cap) {
    uint32_t values[MAX_FIELDS] = {0};

    uint32_t a = (uint32_t)challenge & 7u;
    uint32_t b = ((uint32_t)challenge & 0x38u) >> 3;
    uint32_t k = (uint32_t)(challenge >> 6)
               ^ (uint32_t)(challenge >> 32);

    uint32_t u = p6_table(a, k) ^ 0x1986u;
    uint32_t result = p6_table(b, u) + 0x5880u;

    values[0] = result;
    return write_answer(out, cap, values, 1);
}

int solve_secret(uint64_t challenge, uint64_t context, char *out, size_t cap) {
    if (out == NULL || cap <= 36) {
        return 1;
    }

    uint32_t a = (uint32_t)challenge;
    uint32_t b = (uint32_t)(challenge >> 32);

    uint32_t c = (uint32_t)context;
    uint32_t d = (uint32_t)(context >> 32);

    uint32_t u1 = a ^ b;
    uint32_t u2 = c ^ d;

    uint32_t x1 = c & 3u;

    uint32_t mixed = u1 ^ u2;
    uint32_t rotated = (mixed << 1) | (mixed >> 31);

    uint32_t x2 = (rotated + 0xc64u) ^ 0x785bu;
    x2 ^= (x1 * 0xc64u) ^ (uint32_t)(context >> 16);

    uint32_t x3 = x2 ^ (u2 + x1 + 0x785bu + (u1 >> 1));

    if (cap <= 32) {
        return 1;
    }

    memset(out, ' ', 32);

    int n = snprintf(out + 32, cap - 32, "OPEN%u %u %u",
                 (unsigned)x1,
                 (unsigned)x2,
                 (unsigned)x3);

    if (n < 0 || (size_t)n >= cap - 32) {
        return 1;
    }

    return 0;
}
