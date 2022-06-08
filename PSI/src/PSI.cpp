
#include "PSI.h"
#include <random>
#include <limits>
#include <fstream>

#define TICK std::chrono::high_resolution_clock::now()

  /**
   * Main constructor for LWECryptoParams
   * 700, 1 << 11, 1 << 12, Q_1, 3.19,38, 64, 1 << 6
   * @param n = 700 lattice parameter for additive LWE scheme
   * @param N = 1 << 11 ring dimension for RingGSW/RLWE used in bootstrapping
   * @param &q = 1 << 12 modulus for additive LWE
   * @param &Q = 1152921504606748673 modulus for RingGSW/RLWE used in bootstrapping
   * @param std = 3.19 standard deviation
   * @param baseKS = 38 the base used for key switching
   */
  
  /**
   * @brief clarify the meaning of fbscrypto::CIPHERTEXT_STATE
   * FRESH --- (standard LWE instance, with (n,q))
   * BEFORE_KEYSWITCH --- (standard LWE instance, with (N,Q))
   * BEFORE_MODSWITCH --- (standard LWE instance, with (n,Q))
   * TRIVIAL --- (naked LWE instance (0,q*m/t), with (n,q))
   * TRIVIAL_BEFORE_KEYSWITCH --- (the same as above, except using (N,Q))
   * NOISELESS --- (close to standard LWE instance except for no noise, with (N,q))
   * NOISELESS_BEFORE_KEYSWITCH (the same as above, except using parameter (N,Q))
   * NOISELESS_BEFORE_MODSWITCH (the same as above, excpet using parameter (n,Q))
   * NOISE --- (close to standard LWE instance except for \vec{a} = 0, i.e., (0, q*m/t + e))
   */

namespace PSI {

	void run_threshold_psi(uint64_t modulus, uint32_t paramset_idx, fbscrypto::CIPHERTEXT_STATE state, PSI::PSI_VERSION version){
                /****************************************************
                 *                      set up BF
                 * **************************************************/
                bloom_parameters parameters;
                // How many elements roughly do we expect to insert?
                parameters.projected_element_count = 100;
                // Maximum tolerable false positive probability? (0,1)
                parameters.false_positive_probability = 0.000000000931; // 1 in 2^30
                // Simple randomizer (optional)
                parameters.random_seed = 0xA5A5A5A5;
                parameters.compute_optimal_parameters();
                // parameters.optimal_parameters.number_of_hashes = 20;
                // parameters.optimal_parameters.table_size = 4500;
                std::cout << "Number of hash functions used in BF: " << parameters.optimal_parameters.number_of_hashes << std::endl;
                std::cout << "Size of table used in BF:  " << parameters.optimal_parameters.table_size << std::endl;
                std::cout << "PSI version: " << version << std::endl;
                // Instantiate Bloom Filter for the client side, say C=[0,...,99]
                bloom_filter filter(parameters);
                // Insert some numbers
                for (std::size_t i = 0; i < parameters.projected_element_count; ++i){
                        filter.insert(i+70);
                }
                auto bit_table_pointer = filter.table();
                // std::cout << "Bit Table for BF: " << std::endl;
                // for (int i = 0; i < parameters.optimal_parameters.table_size/bits_per_char; i++)
                //         std::cout << std::hex << (int)(*(bit_table_pointer+i)) << "\t";
                // std::cout << std::endl << std::endl;
                // int c = getchar();

                // Prepare the set of the server side, say S=[70,...,169]
                std::vector<std::size_t> set_S(parameters.projected_element_count);
                for (std::size_t i = 0; i < parameters.projected_element_count; i++)
                        set_S[i] = i;
                

                /****************************************************
                 *                      set up FHE
                 * **************************************************/
                auto start_setup_FHE = std::chrono::high_resolution_clock::now();
                CryptoData data(fbscrypto::FBSFHEPARAMSET_LIST[paramset_idx]);
                auto stop_setup_FHE = std::chrono::high_resolution_clock::now();  
                auto elapsed_setup_FHE = std::chrono::duration_cast<std::chrono::milliseconds>(stop_setup_FHE-start_setup_FHE); 
                std::cerr << "Section Encrypting B.F. "  << " took " << elapsed_setup_FHE.count() << "ms." << std::endl;

                fbscrypto::LWEPrivateKey key;
                if (state == fbscrypto::CIPHERTEXT_STATE::FRESH || state == fbscrypto::CIPHERTEXT_STATE::TRIVIAL)
                        key = data.key;
                else if (state == fbscrypto::CIPHERTEXT_STATE::BEFORE_KEYSWITCH)
                        key = std::make_shared<fbscrypto::LWEPrivateKeyImpl>(fbscrypto::LWEPrivateKeyImpl(data.ctx.GetSkN()));      
                else 
                        key = data.key;          

                // std::vector<NN::CiphertextCRT> entry;
                // std::vector<uint64_t> value = {static_cast<uint64_t>(32)};
                // std::vector<uint64_t> value2 = {static_cast<uint64_t>(1)};

                                      
                std::vector<fbscrypto::LWECiphertext> encrypted_BF;
                for (int i = 0; i < parameters.optimal_parameters.table_size/bits_per_char; i++){ // LWE encrypt B.F.
                        uint64_t mod = modulus;
                        int64_t val;
                        for (int j = 0; j < bits_per_char; j++){
                                if ((*(bit_table_pointer+i) & bit_mask[j]) == bit_mask[j])
                                        val = 1;
                                else 
                                        val = 0;      
                                auto encoded = data.ctx.Encode(val, mod, state);
                                encrypted_BF.push_back(data.ctx.Encrypt(key, encoded, fbscrypto::TRIVIAL_BEFORE_KEYSWITCH));
                        }  
                           
                }
                
                // int count = 0;
                // for (auto encrypt : encrypted_BF){
                //         count++;
                //         fbscrypto::LWEPlaintext pt;
                //         data.ctx.Decrypt(key, encrypt, &pt);
                //         pt = data.ctx.Decode(pt, modulus, fbscrypto::BEFORE_KEYSWITCH);
                //         std::cout << std::dec  << pt << "\t";
                //         if (count == 8){
                //                 std::cout << std::endl;
                //                 count = 0;
                //         }                        
                // }
                // c = getchar();
                /****************************************************
                 *                      perform eSPI_CA
                 * **************************************************/
                
                // auto ct1 = encrypted_BF[0];
                std::vector<size_t> indices_list(filter.hash_count());
                TIME_SECTION_MILLIS("ePSI_CA", auto ct = ePSI_CA(encrypted_BF, set_S, data, modulus, filter, version));
                fbscrypto::LWEPlaintext pt;
                data.ctx.Decrypt(key, ct, &pt);
                pt = data.ctx.Decode(pt, modulus, fbscrypto::BEFORE_KEYSWITCH);
                std::cout << std::dec << "|C \\cap S| result: " << pt << std::endl;
                auto c = getchar();

                /****************************************************
                 * perform post-processing, homomorphically generate 
                 * session key K if below threshold; 
                 * Otherwise, generate random R
                 * **************************************************/
                auto ct_ks = data.ctx.Finalize(ct, fbscrypto::SKIP_STEP::KEYSWITCH);               
                auto t = modulus;
                srand((unsigned) time(0));
                auto r = rand()%t;
                auto threshold = set_S.size()/2;
                std::cout << "random value R: " << r << std::endl;
                c = getchar();
                //generate an LUT for step function
                std::vector<uint32_t> LUT;
                for (int i = 0; i < t; i++){
                        if (i >= threshold)
                                LUT.push_back(static_cast<uint32_t>(r));
                        else
                                LUT.push_back(static_cast<uint32_t>(0)); // assume K = 0
                }

                auto map = [LUT](uint32_t a) { return LUT[a]; };
                auto bootsmap = fbscrypto::BootstrapFunction({map}, t);
                auto result = data.ctx.FullDomainBootstrap(ct_ks, bootsmap, fbscrypto::SKIP_STEP::KEYSWITCH);

                
                data.ctx.Decrypt(key, result, &pt);
                pt = data.ctx.Decode(pt, modulus, state);
                std::cout << "result: " << pt << std::endl;
                std::cout << "False Positive Rate for BF:  " << filter.effective_fpp() << std::endl;
        /*
        // encrypt procedure: first LWE(N,Q), then key-switch to LWE(n,q)
                std::cout << "before encrypt data: " << value[0] << std::endl;
                auto encrypt = data.EncryptCRT(value, fbscrypto::CIPHERTEXT_STATE::BEFORE_KEYSWITCH);
                std::cout << "after encrypt data: " << encrypt << std::endl;
                std::cout << "after decrypt data: " << data.DecryptCRT(encrypt) << std::endl;
                // In this LWE instance setting, (N=2048, Q=1152921504606748673, t=64) is used for TRIVIAL_BEFORE_KEYSWITCH.
                // entry.push_back(data.EncryptCRT(value, fbscrypto::CIPHERTEXT_STATE::TRIVIAL_BEFORE_KEYSWITCH));

                NN::CiphertextCRT encrypt_after_ks = data.DoKeySwitch(encrypt); // change LWE(Q,N,) to LWE(q,n)
                auto dec = data.DecryptCRT(encrypt_after_ks, fbscrypto::TRIVIAL); // use q as LWE modulus
                std::cout << "dec: " << dec << std::endl;
                std::cout << "encrypt_after_ks: " << encrypt_after_ks << std::endl;
        */

        // // encrypt procedure: direct LWE(n,q)
        //         std::ofstream errorfile ("errors.txt");
        //         int correct = 0;
        //         int testNum = 10000;
        //         int add_times = 3;

        //         for (int i = 0; i < testNum; i++){
        //                 std::cout << "before encrypt data: " << value[0] << std::endl;
        //                 auto encrypt = data.EncryptCRT(value, fbscrypto::CIPHERTEXT_STATE::FRESH);
        //                 auto encrypt2 = data.EncryptCRT(value2, fbscrypto::CIPHERTEXT_STATE::FRESH);
        //                 auto encrypt_sum = encrypt;

        //                 for (int j = 0; j < add_times; j++){
        //                         auto encrypt = data.EncryptCRT(value, fbscrypto::CIPHERTEXT_STATE::FRESH);
        //                         auto encrypt2 = data.EncryptCRT(value2, fbscrypto::CIPHERTEXT_STATE::FRESH);
        //                         encrypt_sum += encrypt;
        //                 }
                        
        //                 auto dec = data.DecryptCRT(encrypt_sum, fbscrypto::CIPHERTEXT_STATE::FRESH);
        //                 auto error = data.ErrorCRT(encrypt_sum, fbscrypto::CIPHERTEXT_STATE::FRESH)[0];

        //                 std::cout << "after encrypt data: " << encrypt << std::endl;
        //                 std::cout << "after decrypt data: " << dec << std::endl;
        //                 std::cout << "decrypt data ERROR: " << error << std::endl;
        //                 errorfile << error << std::endl;

        //                 if ( dec.at(0) == (value[0]+add_times*value[0])%moduli[0] )
        //                         correct++;
        //         }
        //         std::cout << "success rate: " << correct << "/" << testNum << std::endl; 
        //         errorfile.close();

        // homo. add with bootstrap
                // int correct = 0;
                // int testNum = 1000;
                // for (int ii = 0; ii < testNum; ii++){
                //         auto encrypt_after_add = encrypt;
                //         for (size_t i = 0; i < 1; i++)
                //         {
                //                 encrypt_after_add = data.CipherAddCRT(encrypt_after_add, encrypt2, fbscrypto::SKIP_STEP::NONE);
                //                 // encrypt_after_add += encrypt2;
                //         }
                        
                //         auto dec = data.DecryptCRT(encrypt_after_add, fbscrypto::CIPHERTEXT_STATE::FRESH);
                //         std::cout << "encrypt_after_add: " << encrypt_after_add << std::endl;
                //         std::cout << "dec: " << dec.at(0) << std::endl;
                //         if (dec.at(0) == 3+1*1)
                //                 correct++;
                // }
                // std::cout << "success rate: " << correct << "/" << testNum << std::endl;
        // // full domain bootstrap
                // std::function<uint64_t(uint64_t, uint64_t)> F; // prepare the evaluation function in bootstrapping
                // std::vector<uint64_t> LUT; //generate an identity LUT
                // auto it = *max_element(std::begin(moduli), std::end(moduli));
                // for (int i = 0; i < it; i++){
                //         LUT.push_back(static_cast<uint64_t>(i));
                //         std::cout << "entry: " << LUT[i] << std::endl;
                // }
                // F = [LUT](uint64_t v, uint64_t q) {
                //         return LUT[v];
                // };

                // std::vector<fbscrypto::BootstrapFunction> EF;
                // for(auto& modulus : moduli)
                //         EF.emplace_back([F, modulus](uint64_t v) {return (F(v, modulus)) % modulus;}, modulus);

                // std::ofstream errorfile ("errors.txt");
                // int correct = 0;
                // int testNum = 1000;
                // int add_times = 1;
                // for (int ii = 0; ii < testNum; ii++){
                //         auto encrypt2 = data.EncryptCRT(value2, fbscrypto::CIPHERTEXT_STATE::FRESH);
                //         auto start = TICK;
                //         auto encrypt_after_bs = data.BootstrapCRT(encrypt2, EF, fbscrypto::SKIP_STEP::NONE);
                //         auto error = data.ErrorCRT(encrypt_after_bs, fbscrypto::CIPHERTEXT_STATE::FRESH)[0];
                //         std::cout << "error: " << error << std::endl;
                //         errorfile << error << std::endl;
                //         auto stop = TICK;
                //         auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(stop-start).count();
                //         std::cout << "The evaluation took " << elapsed << "seconds" << std::endl << std::endl;

                //         for (int i = 0; i < add_times; i++)
                //                 encrypt_after_bs += encrypt_after_bs;
                //         auto dec = data.DecryptCRT(encrypt_after_bs, fbscrypto::CIPHERTEXT_STATE::FRESH);
                //         std::cout << "encrypt_after_bs (after 10 adds): " << encrypt_after_bs << std::endl;
                //         std::cout << "dec: " << dec.at(0) << std::endl;
                //         if (value2[0]+add_times*value2[0] == dec.at(0))
                //                 correct++;                 
                // }              
                // std::cout << "success rate: " << correct << "/" << testNum << std::endl; 
                // errorfile.close();		
	}

        // ePSI_CA returns an LWE encryption of C\cap S
        fbscrypto::LWECiphertext ePSI_CA(std::vector<fbscrypto::LWECiphertext> encrypted_BF, std::vector<std::size_t> set_S, CryptoData data, uint32_t msg_space, bloom_filter filter, PSI::PSI_VERSION version){
                // prepare for bootstrap
                //auto q = ctx.GetParams()->GetLWEParams()->Getq();
                auto t = msg_space;
                //generate an LUT for step function
                std::vector<uint32_t> LUT;
                for (int i = 0; i < t; i++){
                        if (i >= filter.hash_count())
                                LUT.push_back(static_cast<uint32_t>(1));
                        else
                                LUT.push_back(static_cast<uint32_t>(0));
                }

                // full domain bootstrap
                // std::vector<uint64_t> value = {static_cast<uint64_t>(63)};
                // auto encrypt = EncryptCRT(value, fbscrypto::CIPHERTEXT_STATE::NOISE);
                std::function<uint64_t(uint64_t, uint64_t)> F; // prepare the evaluation function in bootstrapping
                F = [LUT](uint64_t v, uint64_t q) {
                        return LUT[v];
                };
                fbscrypto::BootstrapFunction EF([F, t](uint64_t v) {return (F(v, t)) % t;}, t);

                // for every item in sever set (assume here 10 items), perform the following
                fbscrypto::LWECiphertext result, tmp;
                std::vector<std::size_t> indices_list(filter.hash_count());

                for (int item = 0; item < set_S.size(); item++){
                        // Generate the addrs of bit table of Bloom Filter for the server side
                        std::cout << "start of loop: set_S[item] = " << set_S[item] << std::endl;
                        
                        filter.gen_indices(set_S[item], indices_list);
                        // for (auto addr : indices_list){
                        //                 std::cout << std::dec << addr << "\t";
                        // }

                        // homomorphic accumulation (with bootstrap)
                        fbscrypto::LWECiphertextImpl sum(*encrypted_BF[indices_list[0]]);
                        for (int i = 1; i < indices_list.size(); i++){
                                sum = sum + *encrypted_BF[indices_list[i]];
                                // if (i%4 == 0)
                                //         sum = *data.ctx.Bootstrap(std::make_shared<fbscrypto::LWECiphertextImpl>(sum));
                        }
                        
                        fbscrypto::LWEPlaintext pt;
                        auto key = std::make_shared<fbscrypto::LWEPrivateKeyImpl>(fbscrypto::LWEPrivateKeyImpl(data.ctx.GetSkN()));
                        data.ctx.Decrypt(key, std::make_shared<fbscrypto::LWECiphertextImpl>(sum), &pt);
                        pt = data.ctx.Decode(pt, msg_space, fbscrypto::BEFORE_KEYSWITCH);
                        std::cout << std::endl << std::endl;
                        std::cout << item << ", homo ADD result before bootstrap: " << pt << std::endl;
                        // int c = getchar();
                        
                        
                        auto sum_ks = data.ctx.Finalize(std::make_shared<fbscrypto::LWECiphertextImpl>(sum), fbscrypto::SKIP_STEP::KEYSWITCH);
                        // homomorphically decide whether the element is in the B.F. set
                        auto map = [LUT](uint32_t a) { return LUT[a]; };
                        auto bootsmap = fbscrypto::BootstrapFunction({map}, t);
                        if (version == PSI::FDB){
                                if (item == 0)
                                        result = data.ctx.FullDomainBootstrap(sum_ks, bootsmap, fbscrypto::SKIP_STEP::KEYSWITCH);
                                else 
                                        *result += *data.ctx.FullDomainBootstrap(sum_ks, bootsmap, fbscrypto::SKIP_STEP::KEYSWITCH);   
                        }   
                        else {
                                if (item == 0){
                                        tmp = data.ctx.HalfDomainBootstrap(sum_ks, bootsmap, fbscrypto::SKIP_STEP::KEYSWITCH);
                                        result = tmp;
                                }
                                        
                                else{
                                        tmp = data.ctx.HalfDomainBootstrap(sum_ks, bootsmap, fbscrypto::SKIP_STEP::KEYSWITCH);
                                        *result += *tmp; 
                                } 

                                data.ctx.Decrypt(key, tmp, &pt);
                                pt = data.ctx.Decode(pt, msg_space, fbscrypto::BEFORE_KEYSWITCH);
                                std::cout << item << ",  tmp after bootstrap: " << pt << std::endl;
                                std::cout << std::endl << std::endl;            
                        }  
                        
                }

                return result;
        }
}