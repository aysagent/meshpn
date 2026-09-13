/* Parse the actual dependency's descriptors with and without diagnostic CDC. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#define CONFIG_TINYUSB_DESC_CUSTOM_VID 0x303a
#define CONFIG_TINYUSB_DESC_CUSTOM_PID 0x4000
#define CONFIG_TINYUSB_DESC_BCD_DEVICE 0x100
#define CONFIG_TINYUSB_DESC_MANUFACTURER_STRING "test"
#define CONFIG_TINYUSB_DESC_PRODUCT_STRING "test"
#define CONFIG_TINYUSB_DESC_SERIAL_STRING "test"
#define CONFIG_TINYUSB_DESC_CDC_STRING "CDC"
#include MESHVPN_DESCRIPTOR_SOURCE
#include "meshvpn_usb_fifo.h"

int main(void)
{
    const size_t size=sizeof(descriptor_fs_cfg_default);
    const uint8_t expected=CFG_TUD_CDC ? 0x84 : 0x82;
    assert(meshvpn_usb_ncm_in_endpoint(descriptor_fs_cfg_default,size)==expected);
    assert(meshvpn_usb_ncm_in_endpoint(NULL,size)==0);
    uint8_t copy[sizeof(descriptor_fs_cfg_default)];
    for(size_t n=0;n<size;n++)
        assert(meshvpn_usb_ncm_in_endpoint(descriptor_fs_cfg_default,n)==0);
    for(size_t pos=9;pos<size;pos+=descriptor_fs_cfg_default[pos]) {
        memcpy(copy,descriptor_fs_cfg_default,size);
        copy[pos]=0;
        assert(meshvpn_usb_ncm_in_endpoint(copy,size)==0);
        memcpy(copy,descriptor_fs_cfg_default,size);
        if(copy[pos+1]==5 && copy[pos+2]==expected) {
            copy[pos+4]=0; copy[pos+5]=2; /* Not FullSpeed 64-byte bulk. */
            assert(meshvpn_usb_ncm_in_endpoint(copy,size)==0);
            memcpy(copy,descriptor_fs_cfg_default,size);
            copy[pos+2]=0x80; /* EP0 cannot be bulk data. */
            assert(meshvpn_usb_ncm_in_endpoint(copy,size)==0);
        }
        if(copy[pos+1]==5 && copy[pos+2]==(expected & 15)) {
            copy[pos+2]=expected; /* Duplicate IN endpoint is ambiguous. */
            assert(meshvpn_usb_ncm_in_endpoint(copy,size)==0);
        }
        if(copy[pos+1]==11 && copy[pos+5]==13) {
            copy[pos+5]=6; /* ECM is not the NCM experiment. */
            assert(meshvpn_usb_ncm_in_endpoint(copy,size)==0);
        }
    }
    puts("Real USB descriptors: NCM bulk IN selection and malformed input: OK");
}
