#include "protocol.hpp"
#include <iostream>
using namespace cvpn;
static void require(bool b) { if (!b) throw std::runtime_error("test assertion"); }
static Bytes packet(size_t n) {
  Bytes p(n, 0); p[0] = 0x45; p[2] = n >> 8; p[3] = n; p[8] = 64; p[9] = 17;
  uint32_t s = 0; for (size_t i=0; i<20; i+=2) s += (uint16_t(p[i]) << 8) | p[i+1];
  while (s >> 16) s = (s & 65535) + (s >> 16);
  p[10] = (~s) >> 8; p[11] = ~s; return p;
}
int main() {
  for (size_t n : {20, 64, 1400, 1500, 8192, 65535}) {
    auto p = packet(n), f = frame(p.data(), p.size());
    for (size_t chunk : {1, 3, 4, 17, 16384, 65539}) {
      Decoder d; int count = 0;
      for (size_t i=0; i<f.size();) { auto k = std::min(chunk, f.size()-i); d.feed(f.data()+i,k,[&](Bytes b){ require(b==p); ++count; }); i+=k; }
      require(count==1);
    }
    p[10] ^= 1; require(!ipv4(p.data(),p.size()));
  }
  for (uint32_t n : {0U, 1U, 19U, 65536U, 0xffffffffU}) {
    uint8_t b[] = {uint8_t(n>>24),uint8_t(n>>16),uint8_t(n>>8),uint8_t(n)};
    bool failed = false; try { Decoder d; d.feed(b,4,[](Bytes){}); } catch (...) { failed=true; } require(failed);
  }
  Queue q; q.push(Bytes(queue_limit,1)); bool failed=false;
  try { q.push(Bytes(1,2)); } catch (...) { failed=true; } require(failed);
  Bytes out(queue_limit); require(q.read(out.data(),out.size())==out.size()); require(q.empty());
  require(std::all_of(out.begin(),out.end(),[](uint8_t c){return c==1;}));
  std::cout << "protocol PASS\n";
}
