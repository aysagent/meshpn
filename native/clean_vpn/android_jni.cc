#include "android_platform.hpp"
#include <jni.h>
#include <map>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <vector>

namespace cvpn { thread_local AndroidRuntime* android_runtime=nullptr; }
namespace {
std::mutex mutex;
std::map<jlong,std::shared_ptr<cvpn::AndroidRuntime>> runtimes;
jlong serial=0;
std::shared_ptr<cvpn::AndroidRuntime> get(jlong id) {
  std::lock_guard<std::mutex> lock(mutex);
  auto it=runtimes.find(id);return it==runtimes.end()?nullptr:it->second;
}
struct Binding {
  explicit Binding(cvpn::AndroidRuntime* value){cvpn::android_runtime=value;}
  ~Binding(){cvpn::android_runtime=nullptr;}
};
std::string utf(JNIEnv* env,jstring value) {
  if(!value)throw std::runtime_error("path");
  const char* p=env->GetStringUTFChars(value,nullptr);
  if(!p)throw std::runtime_error("path");
  std::string out(p);env->ReleaseStringUTFChars(value,p);return out;
}
int invoke(const char* mode,std::string path){
  char executable[]="clean-vpn-android";
  char* args[]={executable,const_cast<char*>(mode),path.data()};
  return cvpn_android_main(3,args);
}
}
extern "C" JNIEXPORT jlong JNICALL
Java_org_meshpn_client_NativeBridge_create(JNIEnv*,jclass){
  try{std::lock_guard<std::mutex> lock(mutex);auto id=++serial;runtimes.emplace(id,std::make_shared<cvpn::AndroidRuntime>());return id;}
  catch(...){return 0;}
}
extern "C" JNIEXPORT void JNICALL
Java_org_meshpn_client_NativeBridge_stop(JNIEnv*,jclass,jlong id){if(auto r=get(id))r->stop=true;}
extern "C" JNIEXPORT void JNICALL
Java_org_meshpn_client_NativeBridge_networkChanged(JNIEnv*,jclass,jlong id){if(auto r=get(id))++r->network_generation;}
extern "C" JNIEXPORT void JNICALL
Java_org_meshpn_client_NativeBridge_release(JNIEnv*,jclass,jlong id){
  std::lock_guard<std::mutex> lock(mutex);
  auto it=runtimes.find(id);if(it!=runtimes.end()){it->second->stop=true;runtimes.erase(it);}
}
extern "C" JNIEXPORT jboolean JNICALL
Java_org_meshpn_client_NativeBridge_validate(JNIEnv* env,jclass,jstring path){
  try{cvpn::AndroidRuntime runtime;runtime.event=[](const std::string&){};Binding binding(&runtime);
    return invoke("--check-config",utf(env,path))==0;}
  catch(...){return false;}
}
extern "C" JNIEXPORT jint JNICALL
Java_org_meshpn_client_NativeBridge_run(JNIEnv* env,jclass,jlong id,jstring path,jint tun,jobject service){
  auto runtime=get(id);if(!runtime||runtime->running.exchange(true))return 1;
  int result=1;
  try{
    Binding binding(runtime.get());
    jclass cls=env->GetObjectClass(service);
    const auto connect=env->GetMethodID(cls,"connectSocket","(Ljava/lang/String;I)I");
    const auto event=env->GetMethodID(cls,"onNativeEvent","(Ljava/lang/String;)V");
    env->DeleteLocalRef(cls);
    if(!connect||!event)throw std::runtime_error("callbacks");
    runtime->tun_fd=tun;
    runtime->connect=[&](const std::string& address,uint16_t port){
      auto value=env->NewStringUTF(address.c_str());
      if(!value){env->ExceptionClear();return -1;}
      const int fd=env->CallIntMethod(service,connect,value,int(port));
      env->DeleteLocalRef(value);
      if(env->ExceptionCheck()){env->ExceptionClear();return -1;}return fd;
    };
    runtime->event=[&](const std::string& line){
      auto value=env->NewStringUTF(line.c_str());
      if(!value){env->ExceptionClear();runtime->stop=true;return;}
      env->CallVoidMethod(service,event,value);env->DeleteLocalRef(value);
      if(env->ExceptionCheck()){env->ExceptionClear();runtime->stop=true;}
    };
    result=invoke("--config",utf(env,path));
  }catch(...){if(env->ExceptionCheck())env->ExceptionClear();}
  runtime->event={};runtime->connect={};runtime->running=false;return result;
}
