#ifndef CURO_BINARY_TRIE_H
#define CURO_BINARY_TRIE_H

#include <cstdint>
#include <string>

#define IP_BIT_LEN 32

template<typename DATA_TYPE>
struct binary_trie_node{ // 二分トライ木構造のノード
    DATA_TYPE *data; // 保持するデータ
    uint32_t depth; // ルートノードからの深さ
    binary_trie_node *parent; // 親ノード
    binary_trie_node *node_0; // 0側の子ノード
    binary_trie_node *node_1; // 1側の子ノード
};

/**
 * 木構造にノードを作成します
 * @tparam DATA_TYPE
 * @param root
 * @param prefix
 * @param prefix_len
 * @param data
 */
template<typename DATA_TYPE>
void binary_trie_add(binary_trie_node<DATA_TYPE> *root, uint32_t prefix, uint32_t prefix_len, DATA_TYPE *data){
    binary_trie_node<DATA_TYPE> *current = root; // ルートノードから辿る
    // 枝を辿る
    for(int i = 1; i <= prefix_len; ++i){
        if((prefix >> (IP_BIT_LEN - i)) & 0x01){ // 上からiビット目が1だったら
            if(current->node_1 == nullptr){ // 辿る先の枝ががなかったら作る
                current->node_1 = (binary_trie_node<DATA_TYPE> *) calloc(1, sizeof(binary_trie_node<DATA_TYPE>));
                current->node_1->data = 0;
                current->node_1->depth = i;
                current->node_1->parent = current;
            }
            current = current->node_1;
        }else{ // 上からiビット目が0だったら
            if(current->node_0 == nullptr){ // 辿る先の枝ががなかったら作る
                current->node_0 = (binary_trie_node<DATA_TYPE> *) calloc(1, sizeof(binary_trie_node<DATA_TYPE>));
                current->node_0->data = 0;
                current->node_0->depth = i;
                current->node_0->parent = current;
            }
            current = current->node_0;
        }
    }

    current->data = data; // データをセット
}

/**
 * プレフィックスからトライ木を検索します
 * @tparam DATA_TYPE
 * @param root
 * @param prefix
 * @return
 */
template<typename DATA_TYPE>
DATA_TYPE *binary_trie_search(binary_trie_node<DATA_TYPE> *root, uint32_t prefix){ // 検索
    binary_trie_node<DATA_TYPE> *current = root; // ルートノードから辿る
    DATA_TYPE* result = nullptr;
    // 検索するIPアドレスと比較して1ビットずつ辿っていく
    for(int i = 1; i <= IP_BIT_LEN; ++i){
        if(current->data != nullptr){
            result = current->data;
        }
        if((prefix >> (IP_BIT_LEN - i)) & 0x01){ // 上からiビット目が1だったら
            if(current->node_1 == nullptr){
                return result;
            }
            current = current->node_1;
        }else{ // 1ビット目が0だったら
            if(current->node_0 == nullptr){
                return result;
            }
            current = current->node_0;
        }
    }
    return result;
}

/**
 * ノード情報から、プレフィックスを特定します
 * @tparam DATA_TYPE
 * @param target
 * @param root
 * @return
 */
template<typename DATA_TYPE>
uint32_t locate_prefix(binary_trie_node<DATA_TYPE> *target, binary_trie_node<DATA_TYPE> *root){ // ノードから位置を特定
    uint8_t len = target->depth;
    uint32_t result = 0;
    while(target != root){
        if(target->parent->node_1 == target){
            result |= (1 << (32 - len));
        }
        len--;
        target = target->parent; // 上にたどっていく
    }
    return result;
}

#endif //CURO_BINARY_TRIE_H
