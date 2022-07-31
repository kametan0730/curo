#include "command.h"

#include "arp.h"
#include "napt.h"

void command_input(char c){
    if(c == 'a'){
        dump_arp_table_entry();
    }else if(c == 'n'){
        dump_napt_tables();
    }
}