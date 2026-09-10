#include <assert.h>
#include "../components/meshvpn_log/meshvpn_log.c"

static bool fail_alloc, fail_mutex, busy;
static unsigned allocations, installs, forwarded;
static vprintf_like_t hook;
static char forwarded_line[512];
void *heap_caps_malloc(size_t size, uint32_t caps)
{
    allocations++;
    assert(size == MESHVPN_LOG_BUF_SIZE);
    assert(caps == (MALLOC_CAP_8BIT | (CONFIG_SPIRAM ? MALLOC_CAP_SPIRAM : MALLOC_CAP_INTERNAL)));
    return fail_alloc ? NULL : malloc(size);
}
SemaphoreHandle_t xSemaphoreCreateMutex(void) { return fail_mutex ? NULL : (void *)1; }
int xSemaphoreTake(SemaphoreHandle_t mutex, unsigned wait)
{ assert(mutex); assert(wait == 0 || wait == 500); return !busy; }
int xSemaphoreGive(SemaphoreHandle_t mutex) { assert(mutex); return 1; }
static int previous(const char *fmt, va_list args)
{ forwarded++; return vsnprintf(forwarded_line, sizeof(forwarded_line), fmt, args); }
vprintf_like_t esp_log_set_vprintf(vprintf_like_t fn)
{ installs++; hook=fn; return previous; }
esp_reset_reason_t esp_reset_reason(void) { return ESP_RST_POWERON; }
static void emit(const char *fmt, ...)
{ va_list args; va_start(args,fmt); hook(fmt,args); va_end(args); }

int main(void)
{
    char out[MESHVPN_LOG_BUF_SIZE+1];
    assert(meshvpn_log_copy(out,sizeof(out)) == 0 && out[0] == 0);
    fail_alloc=true;
    assert(meshvpn_log_init() == ESP_ERR_NO_MEM && allocations == 1 && installs == 0);
    fail_alloc=false;fail_mutex=true;
    assert(meshvpn_log_init() == ESP_ERR_NO_MEM && !s_buf && installs == 0);
    fail_mutex=false;
    assert(meshvpn_log_init() == ESP_OK && installs == 1);
    assert(meshvpn_log_init() == ESP_OK && allocations == 3 && installs == 1);
    emit("hello %d",42);
    assert(!strcmp(forwarded_line,"hello 42"));
    assert(meshvpn_log_copy(out,sizeof(out)) == 8 && !strcmp(out,"hello 42"));
    busy=true;emit("dropped");
    assert(meshvpn_log_copy(out,sizeof(out)) == 0 && !out[0]);
    busy=false;
    assert(meshvpn_log_copy(out,sizeof(out)) == 8 && !strcmp(out,"hello 42"));
    for (unsigned i=0;i<MESHVPN_LOG_BUF_SIZE+19;i++) emit("%c",'a'+i%26);
    assert(meshvpn_log_copy(out,sizeof(out)) == MESHVPN_LOG_BUF_SIZE);
    for (unsigned i=0;i<MESHVPN_LOG_BUF_SIZE;i++) assert(out[i]==(char)('a'+(i+19)%26));
    char small[8];
    assert(meshvpn_log_copy(small,sizeof(small)) == 7);
    assert(!strcmp(small,out+MESHVPN_LOG_BUF_SIZE-7));
    assert(meshvpn_log_copy(NULL,0) == 0);
    assert(meshvpn_log_copy(small,1) == 0 && small[0] == 0);
    assert(allocations == 3 && forwarded == MESHVPN_LOG_BUF_SIZE+21);
    free(s_buf);
    puts("Log buffer allocation, failure, wrap, truncation, contention and forwarding tests passed");
}
