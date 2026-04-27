#ifndef APP_H
#define APP_H

#include <sgx_urts.h>
#include "Enclave_u.h"

extern sgx_enclave_id_t g_enclave_id;

int  initialize_enclave(const char *enclave_path);
void destroy_enclave(void);

#endif
