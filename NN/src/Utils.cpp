//
// Created by leonard on 27.07.21.
//

#include "Utils.h"

namespace NN {

    fbscrypto::LWECiphertext CryptoData::EncryptNormal(uint64_t value, uint64_t modulus) {
        auto encoded = ctx.Encode(value, modulus, fbscrypto::FRESH);
        return ctx.Encrypt(this->key, encoded);
    }

    CiphertextCRT CryptoData::EncryptCRT(int64_t value, fbscrypto::CIPHERTEXT_STATE from) {
        std::vector<fbscrypto::LWECiphertext> temp;

        for(unsigned long i : moduli) {
            int64_t tmp = value % int64_t(i);
            auto encoded = ctx.Encode(tmp, i, from);
            temp.push_back(ctx.Encrypt(key, encoded, from));
        }

        return {temp, this->moduli};
    }

    CiphertextCRT CryptoData::EncryptCRT(std::vector<uint64_t> &values, fbscrypto::CIPHERTEXT_STATE from) {
        std::vector<fbscrypto::LWECiphertext> temp;

        for(uint32_t i = 0; i < values.size(); i++) {

            uint64_t mod = moduli[i];
            int64_t val = values[i];

            auto encoded = ctx.Encode(val, mod, from);
            temp.push_back(ctx.Encrypt(key, encoded, from));
            //std::cout << "encrypted: " << temp[0]->GetB() << std::endl;
        }

        return {temp, this->moduli};
    }

    CiphertextCRT CryptoData::DoKeySwitch(const CiphertextCRT &crt) {
        std::vector<fbscrypto::LWECiphertext> cts;
        for(uint32_t i = 0; i < moduli.size(); i++) {
            auto& elem = crt.at(i);
            cts.push_back(ctx.Finalize(elem, fbscrypto::SKIP_STEP::KEYSWITCH));
        }

        return {cts, moduli};
    }

    CiphertextCRT CryptoData::DoModswitch(const CiphertextCRT &crt) {
        std::vector<fbscrypto::LWECiphertext> cts;
        for(uint32_t i = 0; i < moduli.size(); i++) {
            auto& elem = crt.at(i);
            cts.push_back(ctx.Finalize(elem, fbscrypto::SKIP_STEP::MODSWITCH));
        }

        return {cts, moduli};
    }

    PlaintextCRT CryptoData::DecryptCRT(const CiphertextCRT &value, fbscrypto::CIPHERTEXT_STATE from) {

        std::vector<uint64_t> values;
        int64_t pt;
        for(uint32_t i = 0; i < moduli.size(); i++) {
            auto ct = value.at(i);
            ctx.Decrypt(this->key, ct, &pt);
            values.push_back(ctx.Decode(pt, moduli[i], from));
        }

        return {values, this->moduli};
    }

    const vector<uint64_t> &CryptoData::GetModuli() const {
        return moduli;
    }

    CiphertextCRT CryptoData::BootstrapCRT(const CiphertextCRT &input, std::vector<fbscrypto::BootstrapFunction>& functions,
                                           fbscrypto::SKIP_STEP step) {

        if (moduli.size() != functions.size()) {
            throw std::invalid_argument("Number of functions does not match number of moduli/ciphertext components");
        }

        std::vector<fbscrypto::LWECiphertext> results;
        for(uint32_t i = 0; i < moduli.size(); i++) {
            results.push_back(ctx.FullDomainBootstrap(input.at(i), functions.at(i), step));
        }

        return {results, this->moduli};
    }

    //user defined function
    CiphertextCRT CryptoData::CipherAddCRT(const CiphertextCRT& input1, const CiphertextCRT& input2, 
                                        fbscrypto::SKIP_STEP step){
        // piece-wise-add input1 and input2
        auto tmp = input1 + input2;
        // return tmp;
        //generate an identity LUT
        std::vector<uint64_t> LUT;
        auto it = *max_element(std::begin(moduli), std::end(moduli));
        for (int i = 0; i < it; i++){
                LUT.push_back(static_cast<uint64_t>(i));
                // std::cout << "entry: " << LUT[i] << std::endl;
        }

        // full domain bootstrap
        // std::vector<uint64_t> value = {static_cast<uint64_t>(63)};
        // auto encrypt = EncryptCRT(value, fbscrypto::CIPHERTEXT_STATE::NOISE);
        std::function<uint64_t(uint64_t, uint64_t)> F; // prepare the evaluation function in bootstrapping
        F = [LUT](uint64_t v, uint64_t q) {
                return LUT[v];
        };

        std::vector<fbscrypto::BootstrapFunction> EF;
        for(auto& modulus : moduli)
                EF.emplace_back([F, modulus](uint64_t v) {return (F(v, modulus)) % modulus;}, modulus);

        // auto encrypt_after_bs = BootstrapCRT(encrypt, EF, fbscrypto::SKIP_STEP::NONE);
        auto encrypt_after_bs = BootstrapCRT(tmp, EF, step);
        return encrypt_after_bs;
    }

    //user defined function
    std::vector<int64_t> CryptoData::ErrorCRT(const CiphertextCRT &value, fbscrypto::CIPHERTEXT_STATE from) {
        //extract the error term from the (vector of) LWE instances
        std::vector<int64_t> errors;
        int64_t pt;
        auto m_Params = ctx.GetParams();
        auto q = m_Params->GetLWEParams()->Getq().ConvertToInt();
        for(uint32_t i = 0; i < moduli.size(); i++) {
            auto ct = value.at(i);
            ctx.Decrypt(this->key, ct, &pt);
            std::cout << "pt: " << pt << std::endl;
            std::cout << "pt': " << (q/moduli[i]) * ctx.Decode(pt, moduli[i], from) << std::endl;
            if (pt >= (q/moduli[i]) * ctx.Decode(pt, moduli[i], from))
                if (pt - (q/moduli[i]) * ctx.Decode(pt, moduli[i], from) < q/2)
                    errors.push_back(pt - (q/moduli[i]) * ctx.Decode(pt, moduli[i], from));      
                else 
                    errors.push_back(pt - (q/moduli[i]) * ctx.Decode(pt, moduli[i], from) -q);             
            else 
                errors.push_back(-((q/moduli[i]) * ctx.Decode(pt, moduli[i], from) - pt));    
        }

        return errors;
    }

    void read_signed_matrix_from_csv(int64_t* buffer, uint32_t shapeX, uint32_t shapeY, std::string& path) {


        std::string line, field;
        std::ifstream iF;

        iF.open(path);
        uint32_t i = 0, j = 0;
        while (std::getline(iF, line) && (i < shapeY) ) {

            std::istringstream s(line);

            while (std::getline(s, field, ',') && (j < shapeX)) {

                int64_t value = std::stoll(field);
                buffer[i * shapeX + j] = value;

                j++;
            }
            j = 0;
            i++;
        }

        iF.close();

    }

    void read_unsigned_matrix_from_csv(uint64_t* buffer, uint32_t shapeX, uint32_t shapeY, std::string& path) {

        std::string line, field;
        std::ifstream iF;

        iF.open(path);
        uint32_t i = 0, j = 0;
        while (std::getline(iF, line) && (i < shapeY)) {

            std::istringstream s(line);

            while (std::getline(s, field, ',') && (j < shapeX)) {

                uint64_t value = std::stoull(field);
                buffer[i * shapeX + j] = value;

                j++;
            }
            j = 0;
            i++;
        }

        iF.close();

    }

    void read_signed_vector_from_csv(int64_t* buffer, uint32_t shapeY, std::string& path) {

        std::string line, field;
        std::ifstream iF;

        iF.open(path);
        uint32_t i = 0;
        while (std::getline(iF, line) && (i < shapeY)) {
            uint64_t value = std::stoll(line);
            buffer[i++] = value;
        }

        iF.close();

    }

    void read_unsigned_vector_from_csv(uint64_t* buffer, uint32_t shapeY, std::string& path) {


        std::string line, field;
        std::ifstream iF;

        iF.open(path);
        uint32_t i = 0;
        while (std::getline(iF, line) && (i < shapeY)) {
            uint64_t value = std::stoull(line);
            buffer[i++] = value;
        }

        iF.close();

    }

    long double evaluate_horner(long double input, const long double* coefs, uint64_t size) {

        if (size == 0)
            return 0.;

        auto accu = coefs[size - 1];
        for(uint32_t i = 1; i < size; i++) {
            accu = (coefs[size - i - 1] + accu * input);
        }

        return accu;
    }



}