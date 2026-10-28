import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]

class AllocTests(unittest.TestCase):
    def test_production_hooks_with_real_cjson(self):
        source=(ROOT/'components/meshvpn_web/meshvpn_web.c').read_text()
        code=source[source.index('static void *web_json_alloc'):source.index('static esp_err_t handler_captive(')]
        sdk=Path(os.environ.get('IDF_PATH',str(Path.home()/'esp/esp-idf-meshpn-v5.5.5')))
        cjson=sdk/'components/json/cJSON'
        header=r'''
#include <assert.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "cJSON.h"
#define MALLOC_CAP_SPIRAM 1
#define MALLOC_CAP_8BIT 2
static unsigned allocations,clock_calls;
static void *heap_caps_malloc_prefer(size_t size,size_t count,...) {
 va_list ap;va_start(ap,count);assert(count==2);
 assert(va_arg(ap,int)==(MALLOC_CAP_SPIRAM|MALLOC_CAP_8BIT));
 assert(va_arg(ap,int)==MALLOC_CAP_8BIT);va_end(ap);
 allocations++;return malloc(size);
}
static time_t test_time(time_t *out){assert(!out);clock_calls++;return 0;}
#define time test_time
'''
        main=r'''
int main(void){
 meshvpn_web_init_allocators();assert(clock_calls==1);
 cJSON *root=cJSON_CreateArray();assert(root);
 for(int i=0;i<2000;i++) assert(cJSON_AddItemToArray(root,cJSON_CreateString("status-node")));
 char *text=cJSON_PrintUnformatted(root);assert(text);
 cJSON *copy=cJSON_Parse(text);assert(copy && cJSON_GetArraySize(copy)==2000);
 cJSON_Delete(root);cJSON_Delete(copy);cJSON_free(text);
 assert(allocations>4000);return 0;
}
'''
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp);(p/'test.c').write_text(header+code+main)
            subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror','-Wno-deprecated-declarations','-fsanitize=address,undefined','-I'+str(cjson),str(p/'test.c'),str(cjson/'cJSON.c'),'-lm','-o',str(p/'test')],check=True)
            subprocess.run([str(p/'test')],check=True)
        startup=(ROOT/'main/app_main.c').read_text().split('void app_main(void)',1)[1]
        assert startup.index('meshvpn_web_init_allocators();')<startup.index('meshvpn_board_init()')

if __name__=='__main__': unittest.main()
