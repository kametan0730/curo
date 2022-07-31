#include "command.h"

#include "arp.h"

void command_input(char c){
    if(c == 'a'){
        dump_arp_table_entry();
    }
}