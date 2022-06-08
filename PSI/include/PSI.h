#ifndef PSI_H
#define PSI_H


#include "fbscontext.h"
#include "setup.h"
#include "CRT.h"
#include "Utils.h"
#include "Dataset.h"
#include "bloom_filter.hpp"

#include <vector>
#include <chrono>
#include <utility>

namespace PSI {
	    /*
     * What kind of ciphertext to output when decrypting
     */
    enum PSI_VERSION {
        FDB,
        TFHE_Improved
    };
	void run_threshold_psi(uint64_t modulus, uint32_t paramset_idx, fbscrypto::CIPHERTEXT_STATE state = fbscrypto::CIPHERTEXT_STATE::FRESH, PSI::PSI_VERSION version = PSI::FDB);
	fbscrypto::LWECiphertext ePSI_CA(std::vector<fbscrypto::LWECiphertext> encrypted_BF, std::vector<std::size_t> set_S, CryptoData data, uint32_t msg_space, bloom_filter filter, PSI::PSI_VERSION version = PSI::FDB);
}

#endif 