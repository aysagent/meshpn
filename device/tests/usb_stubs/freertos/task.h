#pragma once
void test_usb_yield(void);
#define taskYIELD() test_usb_yield()
