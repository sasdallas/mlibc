#include <mlibc/allocator.hpp>

size_t malloc_usable_size(void *p) {
	return getAllocator().get_size(p);
}
