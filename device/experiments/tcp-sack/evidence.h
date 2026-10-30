#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
/* Conservative new-high-water evidence, not a SACK scoreboard. Ignore DSACK,
 * invalid ranges and reports that do not extend the rightmost known range. */
static bool meshpn_sack_evidence(const uint8_t *one,size_t n1,const uint8_t *two,size_t n,
                                uint32_t ack,uint32_t sent,uint32_t *right)
{
    if(n>40||n1>n||(n1&&!one)||(n>n1&&!two))return false;
    uint8_t options[40];if(n1)memcpy(options,one,n1);if(n>n1)memcpy(options+n1,two,n-n1);
    uint32_t newest=*right;bool have=false;
    for(size_t at=0;at<n;){unsigned kind=options[at];if(!kind)break;if(kind==1){at++;continue;}
        if(at+1>=n||options[at+1]<2||options[at+1]>n-at)return false;
        unsigned size=options[at+1];
        if(kind==5){if(size<10||(size-2)%8)return false;
            for(size_t i=at+2;i<at+size;i+=8){uint32_t l=0,r=0;for(unsigned j=0;j<4;j++){l=(l<<8)|options[i+j];r=(r<<8)|options[i+4+j];}
                if((int32_t)(r-l)<=0||(int32_t)(r-sent)>0)return false;
                if((int32_t)(l-ack)<=0)continue;
                if((int32_t)(r-newest)>0){newest=r;have=true;}
            }
        }at+=size;
    }
    if(have) *right=newest;
    return have;
}
