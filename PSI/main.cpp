#include <omp.h>
#include "PSI.h"
using namespace PSI;



int main() {
    std::cout << std::endl << "### RUNNING threshold PSI EVALUATION ###" << std::endl;
    uint32_t m_min = 7, m_max = 7;
    for(uint32_t m = m_min; m <= m_max; m++) {
        std::cout << "[Using modulus = " << ((1 << m)) << "]" << std::endl;
        for(uint32_t i = 0; i < 1; i++) {
            run_threshold_psi(1<<m, i+2, fbscrypto::BEFORE_KEYSWITCH, PSI::TFHE_Improved);
        }
    }
}
