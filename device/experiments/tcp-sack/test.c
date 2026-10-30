#include <assert.h>
#include <stdio.h>
#include "evidence.h"
static void put(uint8_t *p,uint32_t n){p[0]=n>>24;p[1]=n>>16;p[2]=n>>8;p[3]=n;}
int main(void){uint8_t o[40]={1,1,5,10};uint32_t high=100;put(o+4,200);put(o+8,300);
for(unsigned split=0;split<=12;split++){high=100;assert(meshpn_sack_evidence(o,split,o+split,12,100,500,&high));assert(high==300);assert(!meshpn_sack_evidence(o,split,o+split,12,100,500,&high));}
put(o+8,400);assert(meshpn_sack_evidence(o,12,NULL,12,100,500,&high)&&high==400);
put(o+8,600);assert(!meshpn_sack_evidence(o,12,NULL,12,100,500,&high)&&high==400);
put(o+4,50);put(o+8,80);assert(!meshpn_sack_evidence(o,12,NULL,12,100,500,&high));
put(o+4,100);put(o+8,450);assert(!meshpn_sack_evidence(o,12,NULL,12,100,500,&high));
put(o+4,200);o[3]=11;assert(!meshpn_sack_evidence(o,12,NULL,12,100,500,&high));o[3]=10;
for(unsigned n=4;n<12;n++)assert(!meshpn_sack_evidence(o,n,NULL,n,100,500,&high));
assert(!meshpn_sack_evidence(o,41,NULL,41,100,500,&high));assert(!meshpn_sack_evidence(NULL,12,NULL,12,100,500,&high));
high=0xffffff00;put(o+4,0xffffff80);put(o+8,0x40);assert(meshpn_sack_evidence(o,12,NULL,12,0xffffff00,0x100,&high)&&high==0x40);
put(o+8,0x30);assert(!meshpn_sack_evidence(o,12,NULL,12,0xffffff00,0x100,&high));
puts("SACK evidence: bounds, split options, duplicate reports, DSACK, unsent ranges and sequence wrap passed");}
