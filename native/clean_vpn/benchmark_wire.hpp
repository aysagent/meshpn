#pragma once
// Lab application protocol only; never linked into clean-vpn-engine.
#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <stdexcept>
#include <vector>

namespace cvpn::benchmark {
constexpr size_t bytes = 8 * 1024 * 1024;
constexpr size_t rounds = 100, warmup = 5;
using Header = std::array<uint8_t, 16>;
inline void require(bool ok) { if (!ok) throw std::runtime_error("benchmark_protocol_or_io"); }
inline Header header(char mode) {
  require(mode == 'U' || mode == 'D' || mode == 'L');
  return {'C','V','P','N','B','M','1',uint8_t(mode),0,0,0,0,0,0,0,0};
}
template<class Read> void read_all(Read read, uint8_t* p, size_t n) {
  while (n) { auto k = read(p,n); require(k > 0 && size_t(k) <= n); p += k; n -= size_t(k); }
}
template<class Write> void write_all(Write write, const uint8_t* p, size_t n) {
  while (n) { auto k = write(p,n); require(k > 0 && size_t(k) <= n); p += k; n -= size_t(k); }
}
inline uint8_t pattern(size_t offset) { return uint8_t((offset * 31 + offset / 251) % 251); }
template<class Read, class Write> void bulk(Read read, Write write, bool send) {
  std::array<uint8_t,65536> b{};
  for (size_t at = 0; at < bytes; at += b.size()) {
    if (send) {
      for (size_t i=0; i<b.size(); ++i) b[i]=pattern(at+i);
      write_all(write,b.data(),b.size());
    } else {
      read_all(read,b.data(),b.size());
      for (size_t i=0; i<b.size(); ++i) require(b[i]==pattern(at+i));
    }
  }
}
template<class Read, class Write> void serve(const Header& h, Read read, Write write) {
  require(h == header(char(h[7])));
  uint8_t marker='R'; write_all(write,&marker,1); read_all(read,&marker,1); require(marker=='G');
  if (h[7]=='L') {
    std::array<uint8_t,32> b{};
    for (size_t i=0;i<rounds+warmup;++i) { read_all(read,b.data(),b.size()); write_all(write,b.data(),b.size()); }
  } else bulk(read,write,h[7]=='D');
  marker='K'; write_all(write,&marker,1);
  // Receiver acknowledgment makes download completion explicit at the server.
  read_all(read,&marker,1); require(marker=='K');
}
struct Result { double seconds=0, median_ms=0, p95_ms=0; };
template<class Read, class Write> Result client(char mode, Read read, Write write) {
  const auto h=header(mode); write_all(write,h.data(),h.size());
  uint8_t marker=0; read_all(read,&marker,1); require(marker=='R');
  using Clock=std::chrono::steady_clock;
  const auto begin=Clock::now(); marker='G'; write_all(write,&marker,1);
  Result out;
  if (mode=='L') {
    std::vector<double> samples;
    std::array<uint8_t,32> b{}, reply{};
    for(size_t i=0;i<rounds+warmup;++i) {
      for(size_t j=0;j<b.size();++j) b[j]=pattern(i*b.size()+j);
      const auto start=Clock::now(); write_all(write,b.data(),b.size()); read_all(read,reply.data(),reply.size());
      const double ms=std::chrono::duration<double,std::milli>(Clock::now()-start).count(); require(b==reply);
      if(i>=warmup) samples.push_back(ms);
    }
    std::sort(samples.begin(),samples.end()); out.median_ms=(samples[49]+samples[50])/2; out.p95_ms=samples[94];
  } else bulk(read,write,mode=='U');
  read_all(read,&marker,1); require(marker=='K'); write_all(write,&marker,1);
  out.seconds=std::chrono::duration<double>(Clock::now()-begin).count(); require(out.seconds>0);
  return out;
}
}
