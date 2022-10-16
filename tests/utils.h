#ifndef __UTILS_H__
#define __UTILS_H__

struct taus258_state {
	unsigned long s1, s2, s3, s4, s5;
};

struct ioflood_rand {
	struct taus258_state state;
};

void ioflood_rand_init(struct ioflood_rand *rand);
unsigned long ioflood_get_rand(struct ioflood_rand *rand);

#endif /* __UTILS_H__ */
