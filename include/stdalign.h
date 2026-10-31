#ifndef PS3_STDALIGN_H
#define PS3_STDALIGN_H
#define alignas(n) __attribute__((aligned(n)))
#define alignof(type) __alignof__(type)
#endif
