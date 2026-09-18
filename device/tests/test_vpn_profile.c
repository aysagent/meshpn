#include "meshvpn_vpn_profile.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    const char *valid[] = {
        "10.0.0.7", "10.0.0.7/24", "10.0.0.7/0", "10.0.0.7/32",
        "10.0.0.7/24,fd42:42:42::7/64",
        " fd42:42:42::7/64 , 10.0.0.7/24 ",
        "10.0.0.7/24, ::1/128", "10.0.0.7/24, ::/0",
        "10.0.0.7/24, 1:2:3:4:5:6:7:8/64",
        "10.0.0.7/24, ::ffff:192.0.2.1/128",
        "10.0.0.7/24, 1:2:3:4:5:6:192.0.2.1/128",
        "\t10.0.0.7/24,\r\nfd42:42:42::7/64\n",
    };
    const char *invalid[] = {
        "", " ", ",10.0.0.7/24", "10.0.0.7/24,", "10.0.0.7,,::1",
        "10.0.0.7/33", "10.0.0.7/-1", "10.0.0.7/+24", "10.0.0.7/",
        "10.0.0.7/24/24", "10.0.0.7/24junk", "10.0.0.7/ 24",
        "10.0.0.7/999999999999", "10.0.0.7.8/24", "010.0.0.7/24",
        "256.0.0.7/24", "10.0.7/24", "example.com/24", "10.0.0.7/24 10.0.0.8/24",
        "10.0.0.7/24,10.0.0.8/24", "10.0.0.7,10.0.0.7",
        "fd42:42:42::7/64", "10.0.0.7, fd42::7/129",
        "10.0.0.7, 1::2::3", "10.0.0.7, :::1", "10.0.0.7, 1:2:3:4:5:6:7",
        "10.0.0.7, 1:2:3:4:5:6:7:8::", "10.0.0.7, 1:2:3:4:5:6:7:8:9",
        "10.0.0.7, 1:2:3:4:5:6:7:8:", "10.0.0.7, g::1", "10.0.0.7, ::12345",
        "10.0.0.7, ::ffff:256.0.0.1", "10.0.0.7, fe80::1%en0",
        "Address = 10.0.0.7/24", "10.0.0.7/24;fd42::7/64",
    };
    char out[16];
    for (unsigned i = 0; i < sizeof(valid)/sizeof(valid[0]); i++) {
        assert(meshvpn_vpn_profile_address(valid[i], out)); assert(!strcmp(out, "10.0.0.7"));
    }
    for (unsigned i = 0; i < sizeof(invalid)/sizeof(invalid[0]); i++) {
        strcpy(out, "unchanged"); assert(!meshvpn_vpn_profile_address(invalid[i], out));
        assert(!strcmp(out, "unchanged"));
    }
    char long_value[161]; memset(long_value, 'a', 160); long_value[160] = 0;
    assert(!meshvpn_vpn_profile_address(long_value, out));
    assert(!meshvpn_vpn_profile_address(NULL, out));
    assert(!meshvpn_vpn_profile_address("10.0.0.7", NULL));
    puts("WireGuard Address: IPv4/CIDR, IPv6 lists, whitespace and malformed input passed");
}
