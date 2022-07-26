#include "napt.h"

napt_entry* get_napt_entry_by_global(napt_entries* entries, uint32_t address, uint16_t port){

    for(int i = 0; i < NAPT_GLOBAL_PORT_SIZE; ++i){
        if(entries->translation[i].global_address == address and entries->translation[i].global_port == port){
            return &entries->translation[i];
        }
    }
    return nullptr;
}

napt_entry* get_napt_entry_by_local(napt_entries* entries, uint32_t address, uint16_t port){

    for(int i = 0; i < NAPT_GLOBAL_PORT_SIZE; ++i){
        if(entries->translation[i].local_address == address and entries->translation[i].local_port == port){
            return &entries->translation[i];
        }
    }
    return nullptr;
}

napt_entry* create_napt_entry(napt_entries* entries){
    for(int i = 0; i < NAPT_GLOBAL_PORT_SIZE; ++i){
        if(entries->translation[i].global_address == 0){
            entries->translation[i].global_port = NAPT_GLOBAL_PORT_MIN + i;
            return &entries->translation[i];
        }
    }
    return nullptr;
}