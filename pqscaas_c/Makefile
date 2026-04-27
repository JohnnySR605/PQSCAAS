######## SGX SDK settings ########

SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= SIM
SGX_ARCH ?= x64
SGX_DEBUG ?= 1

ifeq ($(shell getconf LONG_BIT), 32)
    SGX_ARCH := x86
endif
ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
    SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
    SGX_COMMON_CFLAGS := -m32
    SGX_LIBRARY_PATH  := $(SGX_SDK)/lib
    SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
    SGX_EDGER8R        := $(SGX_SDK)/bin/x86/sgx_edger8r
else
    SGX_COMMON_CFLAGS := -m64
    SGX_LIBRARY_PATH  := $(SGX_SDK)/lib64
    SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
    SGX_EDGER8R        := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

ifeq ($(SGX_DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
$(error "Cannot set both SGX_DEBUG and SGX_PRERELEASE to 1")
endif
endif

ifeq ($(SGX_DEBUG), 1)
    SGX_COMMON_CFLAGS += -O0 -g
else
    SGX_COMMON_CFLAGS += -O2
endif

ifeq ($(SGX_MODE), HW)
    Trts_Library_Name := sgx_trts
    Service_Library_Name := sgx_tservice
    Urts_Library_Name := sgx_urts
else
    Trts_Library_Name := sgx_trts_sim
    Service_Library_Name := sgx_tservice_sim
    Urts_Library_Name := sgx_urts_sim
endif

######## App Settings ########

App_Cpp_Files := App/App.cpp App/ocalls.cpp App/bench_common.c \
                 experiments_c/exp1_keygen_vs_users.cpp \
                 experiments_c/exp2_phase4_vs_filesize.cpp \
                 experiments_c/exp3_signcrypt_batch_vs_requests.cpp \
                 experiments_c/exp4_phase5_vs_filesize.cpp \
                 experiments_c/exp5_to_7.cpp \
                 experiments_c/exp8_throughput_vs_rate.cpp \
                 experiments_c/exp9_active_enclaves_vs_rate.cpp \
                 experiments_c/exp10_merkle_vs_crl.cpp \
                 experiments_c/exp11_policy_update.cpp \
                 baselines_c/sinha2026/sinha2026.cpp \
                 baselines_c/yu2021/yu2021.cpp \
                 baselines_c/bai2025/bai2025.cpp \
                 Enclave/sha256/sha256.c

App_Include_Paths := -I$(SGX_SDK)/include -Iinclude -IApp -IEnclave/sha256
App_C_Flags       := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes $(App_Include_Paths)
App_Cpp_Flags     := $(App_C_Flags) -std=c++11

App_Link_Flags    := $(SGX_COMMON_CFLAGS) -L$(SGX_LIBRARY_PATH) \
                     -l$(Urts_Library_Name) -lpthread -lm

App_Cpp_Objects := $(App_Cpp_Files:.cpp=.o)
App_Cpp_Objects := $(App_Cpp_Objects:.c=.o)
App_Name := pqscaas_app

######## Enclave Settings ########

Enclave_Version_Script := Enclave/Enclave.lds

Enclave_Cpp_Files := Enclave/Enclave.cpp
Enclave_C_Files   := Enclave/ml_kem/ml_kem_768.c \
                     Enclave/ml_dsa/ml_dsa_65.c \
                     Enclave/aes_gcm/aes_gcm.c \
                     Enclave/sha256/sha256.c \
                     Enclave/sha256/hkdf.c

Enclave_Include_Paths := -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc \
                         -I$(SGX_SDK)/include/libcxx \
                         -Iinclude -IEnclave -IEnclave/sha256 \
                         -IEnclave/ml_kem -IEnclave/ml_dsa -IEnclave/aes_gcm

Enclave_C_Flags   := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie \
                     -ffunction-sections -fdata-sections -fstack-protector-strong \
                     $(Enclave_Include_Paths)
Enclave_Cpp_Flags := $(Enclave_C_Flags) -nostdinc++ -std=c++11

Enclave_Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles \
                      -L$(SGX_LIBRARY_PATH) \
                      -Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
                      -Wl,--start-group -lsgx_tstdc -lsgx_tcxx -lsgx_tcrypto \
                        -l$(Service_Library_Name) -Wl,--end-group \
                      -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
                      -Wl,-pie,-eenclave_entry -Wl,--export-dynamic \
                      -Wl,--defsym,__ImageBase=0 -Wl,--gc-sections \
                      -Wl,--version-script=$(Enclave_Version_Script)

Enclave_Cpp_Objects := $(Enclave_Cpp_Files:.cpp=.o)
Enclave_C_Objects   := $(Enclave_C_Files:.c=.o)

Enclave_Name    := enclave.so
Signed_Enclave_Name := enclave.signed.so
Enclave_Config_File := Enclave/Enclave.config.xml

######## Targets ########

.PHONY: all run clean

all: $(App_Name) $(Signed_Enclave_Name)
	@echo "Build mode: $(SGX_MODE)  (use SGX_MODE=HW for hardware)"

run: all
	@mkdir -p results
	./$(App_Name) all

######## Edger8r: generate untrusted + trusted proxies ########

App/Enclave_u.c: $(SGX_EDGER8R) Enclave/Enclave.edl
	@cd App && $(SGX_EDGER8R) --untrusted ../Enclave/Enclave.edl \
	   --search-path ../Enclave --search-path $(SGX_SDK)/include --search-path ../include
	@echo "GEN => $@"

App/Enclave_u.o: App/Enclave_u.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC  => $@"

Enclave/Enclave_t.c: $(SGX_EDGER8R) Enclave/Enclave.edl
	@cd Enclave && $(SGX_EDGER8R) --trusted Enclave.edl \
	   --search-path . --search-path $(SGX_SDK)/include --search-path ../include
	@echo "GEN => $@"

Enclave/Enclave_t.o: Enclave/Enclave_t.c
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC  => $@"

######## App build ########

App/%.o: App/%.cpp App/Enclave_u.c
	@$(CXX) $(App_Cpp_Flags) -IApp -c $< -o $@
	@echo "CXX => $@"

App/%.o: App/%.c App/Enclave_u.c
	@$(CC) $(App_C_Flags) -IApp -c $< -o $@
	@echo "CC  => $@"

experiments_c/%.o: experiments_c/%.cpp App/Enclave_u.c
	@$(CXX) $(App_Cpp_Flags) -IApp -c $< -o $@
	@echo "CXX => $@"

baselines_c/%.o: baselines_c/%.cpp
	@$(CXX) $(App_Cpp_Flags) -c $< -o $@
	@echo "CXX => $@"

$(App_Name): App/Enclave_u.o $(App_Cpp_Objects)
	@$(CXX) $^ -o $@ $(App_Link_Flags)
	@echo "LINK => $@"

######## Enclave build ########

Enclave/%.o: Enclave/%.cpp Enclave/Enclave_t.c
	@$(CXX) $(Enclave_Cpp_Flags) -c $< -o $@
	@echo "CXX => $@"

Enclave/%.o: Enclave/%.c Enclave/Enclave_t.c
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC  => $@"

$(Enclave_Name): Enclave/Enclave_t.o $(Enclave_Cpp_Objects) $(Enclave_C_Objects)
	@$(CXX) $^ -o $@ $(Enclave_Link_Flags)
	@echo "LINK => $@"

$(Signed_Enclave_Name): $(Enclave_Name)
	@if [ ! -f Enclave/Enclave_private.pem ]; then \
	   openssl genrsa -out Enclave/Enclave_private.pem -3 3072; \
	fi
	@$(SGX_ENCLAVE_SIGNER) sign -key Enclave/Enclave_private.pem -enclave $(Enclave_Name) \
	   -out $@ -config $(Enclave_Config_File)
	@echo "SIGN => $@"

######## Cleanup ########

clean:
	@if [ -d $(App_Name) ]; then \
	    echo "Skipping remove: $(App_Name) is a directory"; \
	else \
	    rm -f $(App_Name); \
	fi
	rm -f $(Enclave_Name) $(Signed_Enclave_Name)
	rm -f App/Enclave_u.* App/Enclave_u.o
	rm -f Enclave/Enclave_t.* Enclave/Enclave_t.o
	rm -f $(App_Cpp_Objects) $(Enclave_Cpp_Objects) $(Enclave_C_Objects)
	find . -name "*.o" -delete
