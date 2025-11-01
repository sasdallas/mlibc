#include <unistd.h>

extern "C" int get_nprocs(void) {
	return sysconf(_SC_NPROCESSORS_ONLN);
}

extern "C" int get_nprocs_conf(void) {
	return sysconf(_SC_NPROCESSORS_CONF);
}
