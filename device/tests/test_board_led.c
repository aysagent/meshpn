#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include "meshvpn_board.h"
#include "driver/gpio.h"

static meshvpn_board_config_t board = {.pin_led=21};
static unsigned level=1, writes;
const meshvpn_board_config_t *meshvpn_board_get_config(void) { return &board; }
esp_err_t gpio_set_level(int pin,uint32_t value)
{
    assert(pin==21 && value<=1);level=value;writes++;return ESP_OK;
}
static void *blink(void *arg)
{
    (void)arg;
    for(int i=0;i<10000;i++)meshvpn_board_led_set(i%2);
    return NULL;
}
int main(void)
{
    assert(meshvpn_board_led_enabled());
    meshvpn_board_led_set(true);assert(level==0);
    meshvpn_board_led_enable(false);assert(level==1);
    meshvpn_board_led_set(false);meshvpn_board_led_set(true);assert(level==1);
    meshvpn_board_led_enable(true);assert(level==0); /* restore requested status */
    meshvpn_board_led_set(false);assert(level==1);
    pthread_t thread;assert(!pthread_create(&thread,NULL,blink,NULL));
    meshvpn_board_led_enable(false);
    assert(!pthread_join(thread,NULL));assert(level==1 && !meshvpn_board_led_enabled());
    meshvpn_board_led_enable(true);assert(level==0);
    board.pin_led=-1;unsigned before=writes;
    meshvpn_board_led_set(true);meshvpn_board_led_enable(false);assert(writes==before);
    puts("LED gating, active-low output, concurrent blinking and unsupported board passed");
}
