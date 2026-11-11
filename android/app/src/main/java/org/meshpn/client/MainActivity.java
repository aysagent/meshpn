package org.meshpn.client;

import android.app.*;
import android.content.*;
import android.graphics.Color;
import android.net.VpnService;
import android.os.*;
import android.text.InputFilter;
import android.view.*;
import android.widget.*;
import java.io.*;
import java.nio.charset.StandardCharsets;

/** Small native TV UI: every action is focusable and works with D-pad/OK/Back. */
public final class MainActivity extends Activity {
    private static final int PERMISSION=1, IMPORT=2, EXPORT=3;
    private final Handler handler=new Handler(Looper.getMainLooper());
    private TextView status, details, counters, message;
    private Button connect, fileImport, pasteImport, check, selectServer, deleteServer;
    private CheckBox profile, autostart;
    private boolean importing=false, configured=false, hasProfile=false, checking=false;
    private final SharedPreferences.OnSharedPreferenceChangeListener settings=(prefs,key)->{
        if("active".equals(key))runOnUiThread(()->{if(!isDestroyed())loadSummary();});
    };
    private final Runnable refresh=new Runnable(){public void run(){render();handler.postDelayed(this,1000);}};
    private int dp(int n){return Math.round(n*getResources().getDisplayMetrics().density);}
    private TextView text(LinearLayout parent,String value,int size){
        TextView v=new TextView(this);v.setText(value);v.setTextSize(size);v.setTextColor(Color.rgb(226,237,241));
        v.setPadding(0,dp(6),0,dp(6));parent.addView(v);return v;
    }
    private Button button(LinearLayout parent,String value,Runnable action){
        Button b=new Button(this);b.setText(value);b.setAllCaps(false);b.setTextSize(18);b.setMinHeight(dp(56));
        b.setFocusable(true);b.setOnClickListener(v->action.run());
        parent.addView(b,new LinearLayout.LayoutParams(-1,-2));return b;
    }
    @Override public void onCreate(Bundle saved){
        super.onCreate(saved);
        ScrollView scroll=new ScrollView(this);scroll.setFillViewport(true);
        LinearLayout page=new LinearLayout(this);page.setOrientation(LinearLayout.VERTICAL);
        page.setPadding(dp(48),dp(24),dp(48),dp(32));page.setBackgroundColor(Color.rgb(18,32,43));scroll.addView(page);
        text(page,"Clean VPN",32);text(page,"Android TV · boring-tls",17);
        status=text(page,"Отключён",26);details=text(page,"Импортируйте файл подключения",17);counters=text(page,"",16);
        connect=button(page,"Подключить",()->{
            if(VpnClientService.busy())VpnClientService.disconnect(this);else requestConnection();render();
        });
        message=text(page,"Управление: стрелки · OK · Назад",16);
        fileImport=button(page,"Импортировать конфигурацию из файла",()->{
            try{Intent i=new Intent(Intent.ACTION_OPEN_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE).setType("*/*");startActivityForResult(i,IMPORT);}
            catch(ActivityNotFoundException e){showPaste();}
        });
        pasteImport=button(page,"Вставить конфигурацию JSON",this::showPaste);
        selectServer=button(page,"Выбрать сохранённый сервер",this::selectServer);
        deleteServer=button(page,"Удалить выбранную конфигурацию",()->new AlertDialog.Builder(this)
            .setTitle("Удалить конфигурацию и её ключ с устройства?")
            .setMessage("Регистрация клиента на exit останется. Для повторного подключения потребуется импорт bundle.")
            .setNegativeButton("Отмена",null).setPositiveButton("Удалить",(d,w)->{
                try{ConfigStore.deleteActive(this);loadSummary();}catch(Exception e){message.setText("Не удалось удалить конфигурацию");}
            }).show());
        profile=new CheckBox(this);profile.setText("Использовать браузерный TLS-профиль из конфигурации");profile.setTextSize(17);profile.setMinHeight(dp(56));page.addView(profile);
        profile.setOnClickListener(v->{
            try{ConfigStore.setProfile(this,profile.isChecked());}
            catch(IOException e){profile.setChecked(ConfigStore.prefs(this).getBoolean("profile",true));message.setText(e.getMessage());}
        });
        autostart=new CheckBox(this);autostart.setText("Подключаться после загрузки устройства");autostart.setTextSize(17);autostart.setMinHeight(dp(56));page.addView(autostart);
        autostart.setOnClickListener(v->{
            ConfigStore.prefs(this).edit().putBoolean("autostart",autostart.isChecked()).apply();
            if(autostart.isChecked())message.setText("Сначала подключитесь вручную и подтвердите разрешение Android. Автозапуск зависит от прошивки.");
        });
        check=button(page,"Проверить доступность HTTPS",this::checkConnection);
        button(page,"Показать диагностику",()->new AlertDialog.Builder(this).setTitle("Диагностика (без ключей)")
            .setMessage(report()).setPositiveButton("Закрыть",null).setNeutralButton("Сохранить",(d,w)->exportReport()).show());
        text(page,"DNS идёт через VPN при подключении. Kill switch отсутствует: после отключения или остановки приложения работает обычный интернет. IPv6 в этой версии блокируется на время VPN.",15);
        setContentView(scroll);loadSummary();(configured?connect:fileImport).requestFocus();
    }
    private void loadSummary(){
        try{
            Enrollment c=ConfigStore.load(this);configured=true;hasProfile=c.profile!=null;
            details.setText(c.name+" · "+c.address+":"+c.port+"\nАдрес клиента: "+c.peer+" · TLS: "+c.serverName
                +"\nDNS: "+android.text.TextUtils.join(", ",c.dns)+"\nTLS-профиль: "+(hasProfile?"доступен импортированный":"стандартный BoringSSL"));
        }catch(Exception e){configured=false;hasProfile=false;details.setText("Импортируйте клиентский bundle. Нужен отдельный ключ для этого устройства.");}
        profile.setChecked(ConfigStore.prefs(this).getBoolean("profile",true)&&hasProfile);
        autostart.setChecked(ConfigStore.prefs(this).getBoolean("autostart",false));render();
    }
    private void render(){
        boolean busy=VpnClientService.busy();
        status.setText(VpnClientService.label(VpnClientService.state));
        status.setTextColor(VpnClientService.state.equals("ready")?Color.rgb(65,214,195):Color.WHITE);
        counters.setText("Пакеты ↑ "+VpnClientService.tx+"   ↓ "+VpnClientService.rx);
        connect.setText(busy?"Отключить":"Подключить");
        connect.setEnabled(!importing&&(busy||configured)&&!VpnClientService.state.equals("stopping"));
        fileImport.setEnabled(!busy&&!importing);pasteImport.setEnabled(!busy&&!importing);
        selectServer.setEnabled(!busy&&!importing);deleteServer.setEnabled(configured&&!busy&&!importing);
        profile.setEnabled(hasProfile&&!busy&&!importing);autostart.setEnabled(configured&&!importing);
        check.setEnabled(!checking);
    }
    private void requestConnection(){
        try{
            Intent permission=VpnService.prepare(this);
            if(permission!=null)startActivityForResult(permission,PERMISSION);else VpnClientService.start(this);
        }catch(Exception|LinkageError e){message.setText("Не удалось запустить VPN. Проверьте поддержку VPN в прошивке и ABI приложения.");}
    }
    private void selectServer(){
        File[] dirs=ConfigStore.saved(this);
        if(dirs.length==0){message.setText("Нет сохранённых конфигураций");return;}
        String[] labels=new String[dirs.length];
        for(int i=0;i<dirs.length;i++)try{
            Enrollment e=new Enrollment(ConfigStore.read(new FileInputStream(new File(dirs[i],"bundle.json"))));
            labels[i]=e.name+" · "+e.address+":"+e.port;
        }catch(Exception e){labels[i]="Повреждённая конфигурация";}
        new AlertDialog.Builder(this).setTitle("Сохранённые серверы").setItems(labels,(d,which)->{
            try{ConfigStore.select(this,dirs[which]);loadSummary();}catch(Exception e){message.setText("Не удалось выбрать конфигурацию. Проверьте свободное место и отключите VPN.");}
        }).setNegativeButton("Отмена",null).show();
    }
    private void showPaste(){
        EditText input=new EditText(this);input.setMinLines(4);input.setMaxLines(8);input.setTextSize(14);
        input.setSaveEnabled(false);
        input.setInputType(android.text.InputType.TYPE_CLASS_TEXT|android.text.InputType.TYPE_TEXT_FLAG_MULTI_LINE|android.text.InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        input.setFilters(new InputFilter[]{new InputFilter.LengthFilter(Enrollment.LIMIT)});
        new AlertDialog.Builder(this).setTitle("Вставьте клиентский bundle JSON").setView(input)
            .setNegativeButton("Отмена",null).setPositiveButton("Импорт",(d,w)->{
                String value=input.getText().toString();input.setText("");importConfig(()->value);
            }).show();
    }
    interface Source {String read() throws Exception;}
    private void importConfig(Source source){
        if(importing||VpnClientService.busy())return;
        if(ConfigStore.saved(this).length>=8){message.setText("Сохранено 8 конфигураций. Удалите ненужную перед импортом.");return;}
        importing=true;message.setText("Проверка и сохранение конфигурации…");render();
        new Thread(()->{
            String result;
            try{Enrollment c=ConfigStore.install(getApplicationContext(),source.read());result=c.fromCombo?
                "Импортировано. Из combo-конфигурации используется только boring-tls.":"Конфигурация импортирована и проверена.";}
            catch(Exception e){result="Импорт отклонён. Проверьте формат bundle, CA, отдельный ключ клиента и TLS-профиль.";}
            catch(LinkageError e){result="Native-библиотека недоступна для этой архитектуры.";}
            final String done=result;
            runOnUiThread(()->{if(isDestroyed())return;importing=false;message.setText(done);loadSummary();});
        },"vpn-import").start();
    }
    private String report(){
        return "Clean VPN Android TV "+BuildConfig.VERSION_NAME+"\nAndroid "+Build.VERSION.RELEASE+" (API "+Build.VERSION.SDK_INT+")"
            +"\nABI: "+android.text.TextUtils.join(", ",Build.SUPPORTED_ABIS)+"\nTransport: boring-tls\nState: "+VpnClientService.state
            +"\nLast session error: "+VpnClientService.lastError+"\nTX packets: "+VpnClientService.tx+"; RX packets: "+VpnClientService.rx
            +"\nKill switch: absent\n\n"+VpnClientService.logs();
    }
    private void exportReport(){
        try{startActivityForResult(new Intent(Intent.ACTION_CREATE_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE)
            .setType("text/plain").putExtra(Intent.EXTRA_TITLE,"clean-vpn-diagnostic.txt"),EXPORT);}
        catch(ActivityNotFoundException e){
            ((android.content.ClipboardManager)getSystemService(CLIPBOARD_SERVICE)).setPrimaryClip(ClipData.newPlainText("VPN diagnostics",report()));
            message.setText("Диагностика скопирована в буфер обмена");
        }
    }
    private void checkConnection(){
        if(checking)return;checking=true;render();message.setText("Проверка example.org через текущую сеть…");
        final long epoch=VpnClientService.connectionEpoch;
        boolean accepted=HttpsProbe.start(done->runOnUiThread(()->{
            if(isDestroyed())return;checking=false;
            message.setText(epoch==VpnClientService.connectionEpoch?done:"VPN изменился во время проверки. Повторите её для текущего соединения.");render();
        }));
        if(!accepted){checking=false;message.setText("Предыдущая сетевая проверка ещё освобождает ресурсы. Повторите позже.");render();}
    }
    @Override protected void onActivityResult(int request,int result,Intent data){
        super.onActivityResult(request,result,data);
        if(result!=RESULT_OK){if(request==PERMISSION)message.setText("Разрешение на VPN не выдано. Подключение не запущено.");return;}
        if(request==PERMISSION){try{VpnClientService.start(this);}catch(Exception e){message.setText("Не удалось запустить службу VPN");}}
        if(request==IMPORT&&data!=null&&data.getData()!=null){final android.net.Uri uri=data.getData();importConfig(()->ConfigStore.read(getContentResolver().openInputStream(uri)));}
        if(request==EXPORT&&data!=null&&data.getData()!=null){
            try(OutputStream out=getContentResolver().openOutputStream(data.getData(),"wt")){
                if(out==null)throw new IOException();out.write(report().getBytes(StandardCharsets.UTF_8));message.setText("Диагностика сохранена");
            }catch(Exception e){message.setText("Не удалось сохранить диагностику");}
        }
    }
    @Override protected void onResume(){super.onResume();ConfigStore.prefs(this).registerOnSharedPreferenceChangeListener(settings);loadSummary();handler.removeCallbacks(refresh);handler.post(refresh);}
    @Override protected void onPause(){ConfigStore.prefs(this).unregisterOnSharedPreferenceChangeListener(settings);handler.removeCallbacks(refresh);super.onPause();}
}
