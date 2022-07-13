#ifndef RAW_SOCKET_BINARY_TRIE_H
#define RAW_SOCKET_BINARY_TRIE_H

#include <cstdint>
#include <string>

#define IP_BIT_LEN 32

template<typename DATA_TYPE>
struct binary_trie_node{
    DATA_TYPE* data;

    binary_trie_node* node_0;
    binary_trie_node* node_1;
};

template<typename DATA_TYPE>
void add(binary_trie_node<DATA_TYPE>* root, uint32_t prefix, uint32_t prefix_len, DATA_TYPE* data){

    binary_trie_node<DATA_TYPE>* current = root;

    for(int i = 1; i <= prefix_len; ++i){
        if((prefix >> (IP_BIT_LEN - i)) & 0x01){ // 上からiビット目が1だったら
            if(current->node_1 == nullptr){
                current->node_1 = (binary_trie_node<DATA_TYPE>*) calloc(1, sizeof(binary_trie_node<DATA_TYPE>));
                current->node_1->data = 0;
            }
            current = current->node_1;
        }else{ // 上からiビット目が0だったら
            if(current->node_0 == nullptr){
                current->node_0 = (binary_trie_node<DATA_TYPE>*) calloc(1, sizeof(binary_trie_node<DATA_TYPE>));
                current->node_0->data = 0;
            }
            current = current->node_0;
        }
    }

    current->data = data;
}

template<typename DATA_TYPE>
DATA_TYPE* search(binary_trie_node<DATA_TYPE>* root, uint32_t prefix){

    binary_trie_node<DATA_TYPE>* current = root;

    for(int i = 1; i <= IP_BIT_LEN; ++i){
        if((prefix >> (IP_BIT_LEN - i)) & 0x01){ // 上からiビット目が1だったら
            if(current->node_1 == nullptr){
                return current->data;
            }
            current = current->node_1;
        }else{ // 1ビット目が0だったら
            if(current->node_0 == nullptr){
                return current->data;
            }
            current = current->node_0;
        }
    }
    return current->data;
}


#endif //RAW_SOCKET_BINARY_TRIE_H
