/*
   Description: This example demonstrates the basic behavior of BF used in 
   the context of PSI protocol.
   i.e., generate the BF bit-table for the client side
   generate the addr/index of BF bit-table for each item in the server side set
*/

#include <iostream>
#include <string>

#include "bloom_filter.hpp"
using namespace PSI;

int main()
{
   bloom_parameters parameters;

   // How many elements roughly do we expect to insert?
   parameters.projected_element_count = 1;

   // Maximum tolerable false positive probability? (0,1)
   parameters.false_positive_probability = 0.000000000931; // 1 in 2^30

   // Simple randomizer (optional)
   parameters.random_seed = 0xA5A5A5A5;

   if (!parameters)
   {
      std::cout << "Error - Invalid set of bloom filter parameters!" << std::endl;
      return 1;
   }

   parameters.compute_optimal_parameters();
   std::cout << "Number of hash functions used in BF: " << parameters.optimal_parameters.number_of_hashes << std::endl;
   std::cout << "Size of table used in BF:  " << parameters.optimal_parameters.table_size << std::endl;

   parameters.optimal_parameters.number_of_hashes = 10;
   parameters.optimal_parameters.table_size = 4500;
   std::cout << "Number of hash functions used in BF: " << parameters.optimal_parameters.number_of_hashes << std::endl;
   std::cout << "Size of table used in BF:  " << parameters.optimal_parameters.table_size << std::endl;

   // Instantiate Bloom Filter for the client side, say C=[0,...,99]
   bloom_filter filter(parameters);

   // Insert some numbers
   for (std::size_t i = 0; i < parameters.projected_element_count; ++i){
      filter.insert(i);
   }
   auto bit_table_pointer = filter.table();
   std::vector<int> bit_table(parameters.optimal_parameters.table_size);
   std::cout << "Bit Table for BF: " << std::endl;
   for (int i = 0; i < parameters.optimal_parameters.table_size/bits_per_char; i++)
      std::cout << std::hex << (int)(*(bit_table_pointer+i)) << "\t";
   std::cout << std::endl << std::endl;
   for (int byte = 0; byte < bit_table.size()/bits_per_char; byte++){
      for (int bit = 0; bit < bits_per_char; bit++){
         if ( (*(bit_table_pointer+byte) & bit_mask[bit]) == bit_mask[bit] )
            bit_table[byte*bits_per_char+bit] = 1;
         else 
            bit_table[byte*bits_per_char+bit] = 0;   
      }
   }

    // Generate the addrs of bit table of Bloom Filter for the server side, say S=[50,...,149]
    std::vector<size_t> set_S(parameters.projected_element_count);
    std::vector<size_t> indices_list(filter.hash_count());
    for (std::size_t i = 0; i < parameters.projected_element_count; ++i){
        set_S[i] = i;
    }

   std::cout << "Generate the addrs of bit table of Bloom Filter for the server side: " << std::endl;
   int cardinality = 0;
    for (std::size_t i = 0; i < set_S.size(); ++i){
       filter.gen_indices(set_S[i], indices_list);
       int sum = 0;
       for (auto addr : indices_list){
         // auto byte = addr / bits_per_char;
         // auto bit = addr % bits_per_char;
         // std::string str = "(" + std::to_string(byte) + ", " + std::to_string(bit) + ")  ";
         // std::cout << str;
         // if ( (*(bit_table_pointer+byte) & bit_mask[bit]) == bit_mask[bit] )
         //    sum++;
         std::cout << std::dec << addr << "\t";
         sum += bit_table[addr];
       }
       std::cout << std::dec << "sum: " << sum << std::endl << std::endl;
       if (sum == parameters.optimal_parameters.number_of_hashes)
         cardinality++;
    }

   std::cout << "Cardinality for S \\cap C:  " << cardinality << std::endl;        
   std::cout << "False Positive Rate for BF:  " << filter.effective_fpp() << std::endl;

   return 0;
}