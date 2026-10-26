// Included only by the C++ integration harness, after Child/packet/rss helpers.
// All data packets and backpressure work remain in C++, never Node callbacks.
static Bytes budget_packet(size_t n,bool inbound,int index,uint8_t seed){
  auto b=packet(n,inbound,seed);b[inbound?19:15]=index+2;b[10]=b[11]=0;
  uint32_t sum=0;for(int i=0;i<20;i+=2)sum+=(uint16_t(b[i])<<8)|b[i+1];
  while(sum>>16)sum=(sum&65535)+(sum>>16);
  b[10]=(~sum)>>8;b[11]=~sum;return b;
}
static uint64_t budget_drain(Child& peer,int index,bool single=false){
  const auto expected=budget_packet(16384,true,index,171);Bytes b(65536);uint64_t count=0;
  for(int i=0;i<(single?1:2048);i++){
    auto n=recv(peer.packet,b.data(),b.size(),MSG_DONTWAIT);
    if(n<0){require(errno==EAGAIN||errno==EWOULDBLOCK,"budget_drain");break;}
    require(n==ssize_t(expected.size())&&std::equal(expected.begin(),expected.end(),b.begin()),"budget_flood_integrity_or_peer");count++;
  }
  return count;
}
static double budget_probe(Child& server,Child& client,int index){
  const auto start=Clock::now();
  for(bool inbound:{false,true}){
    auto& from=inbound?server:client;auto& to=inbound?client:server;
    const auto expected=budget_packet(1400,inbound,index,23);Bytes b(65536);
    const auto deadline=Clock::now()+std::chrono::seconds(2);
    while(send(from.packet,expected.data(),expected.size(),MSG_DONTWAIT)<0){
      require((errno==EAGAIN||errno==EWOULDBLOCK)&&Clock::now()<deadline,"budget_probe_send");
      pollfd p{from.packet,POLLOUT,0};poll(&p,1,5);
    }
    pollfd p{to.packet,POLLIN,0};require(poll(&p,1,2000)>0,"budget_probe_blocked");
    const auto n=recv(to.packet,b.data(),b.size(),0);
    require(n==ssize_t(expected.size())&&std::equal(expected.begin(),expected.end(),b.begin()),"budget_probe_integrity");
  }
  return std::chrono::duration<double,std::milli>(Clock::now()-start).count();
}
static size_t budget_queued(const json& s){
  return s.at("outgoing_bytes").get<size_t>()+s.at("network_bytes").get<size_t>()+s.at("packet_bytes").get<size_t>();
}
static void budget_validate(const json& s){
  const auto live=s.at("live_sessions").get<size_t>();
  require(s.at("created").get<size_t>()-s.at("destroyed").get<size_t>()==live,"budget_session_accounting");
  require(s.at("socket_memory_samples").get<size_t>()<=live,"budget_kernel_socket_sample_count");
  require(s.at("largest_queue_bytes").get<size_t>()<=queue_limit&&budget_queued(s)<=live*queue_limit*3,"budget_queue_bound");
}
static void budget_wait_sessions(Child& process,size_t wanted){
  const auto end=Clock::now()+std::chrono::seconds(3);
  while(Clock::now()<end){
    const auto s=process.budget_status(false).at("fixture_h2_budget");budget_validate(s);
    if(s.at("live_sessions")==wanted){if(!wanted)require(budget_queued(s)==0,"budget_destroyed_queues");return;}
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  throw std::runtime_error("budget_session_cleanup_timeout");
}
static void h2_budget(const char* exe,const char* directory,const char* exit_config,int count){
  require(std::getenv("CVPN_TEST_H2_BUDGET")!=nullptr,"budget_mode_required");
  Child server(exe,exit_config);server.await_state("listening");
  const auto idle_fds=fd_count(server.pid);
  std::vector<std::string> configs;std::vector<std::unique_ptr<Child>> peers;
  for(int i=0;i<count;i++){
    configs.push_back(std::string(directory)+"/client-"+std::to_string(i)+".json");
    peers.push_back(std::make_unique<Child>(exe,configs.back().c_str()));peers.back()->await_state("ready");
  }
  budget_wait_sessions(server,count);
  for(int i=0;i<count;i++)budget_probe(server,*peers[i],i);
  const auto baseline_rss=rss(server.pid);json phases=json::array(),recoveries=json::array();
  long previous_recovered=0;const auto began=Clock::now();
  for(int cycle=0;cycle<3;cycle++){
    for(int stage=0;stage<2;stage++){
      const int slow=stage==0?1:std::max(1,count-1);
      uint64_t accepted=0,drained=0,probes=0,samples=0,tick=0;size_t largest=0,exit_queue_peak=0,client_queue_peak=0,exit_fd_peak=0;
      std::vector<uint64_t> injected_by_client(count,0);
      std::vector<size_t> client_largest_queues(count,0);
      long exit_peak=0,clients_peak=0,client_peak=0;double worst_probe=0;
      uint64_t tcp_receive_peak=0,tcp_send_peak=0;
      bool kernel_memory_available=true;
      const auto start=Clock::now(),end=start+std::chrono::seconds(2);
      auto next_sample=start,next_probe=start,next_drain=start;
      const auto drops_before=server.budget_status().at("dropped_packets").get<uint64_t>();
      while(Clock::now()<end){
        for(int offset=0;offset<slow;offset++){
          const int index=(tick+offset)%slow;
          const auto b=budget_packet(16384,true,index,171);
          for(int batch=0;batch<16;batch++){
            const auto n=send(server.packet,b.data(),b.size(),MSG_DONTWAIT);
            if(n<0){require(errno==EAGAIN||errno==EWOULDBLOCK,"budget_flood_send");break;}
            require(n==ssize_t(b.size()),"budget_flood_partial");accepted++;injected_by_client[index]++;
          }
        }
        tick++;
        if(stage==0&&Clock::now()>=next_drain){drained+=budget_drain(*peers[0],0,true);next_drain=Clock::now()+std::chrono::milliseconds(50);}
        if(count>slow&&Clock::now()>=next_probe){
          for(int i=slow;i<count;i++){worst_probe=std::max(worst_probe,budget_probe(server,*peers[i],i));probes++;}
          next_probe=Clock::now()+std::chrono::milliseconds(100);
        }
        if(Clock::now()>=next_sample){
          const auto status=server.budget_status();const auto s=status.at("fixture_h2_budget");budget_validate(s);
          kernel_memory_available&=s.at("socket_memory_samples")==s.at("live_sessions");
          require(s.at("live_sessions")==count,"budget_exit_session_lost");
          exit_queue_peak=std::max(exit_queue_peak,budget_queued(s));largest=std::max(largest,s.at("largest_queue_bytes").get<size_t>());
          exit_peak=std::max(exit_peak,rss(server.pid));exit_fd_peak=std::max(exit_fd_peak,fd_count(server.pid));
          long total=0;size_t queues=0;
          uint64_t tcp_receive=s.at("tcp_receive_alloc_bytes"),tcp_send=s.at("tcp_send_queued_bytes");
          for(int i=0;i<count;i++){
            auto& peer=peers[i];
            const auto c=peer->budget_status().at("fixture_h2_budget");budget_validate(c);require(c.at("live_sessions")==1,"budget_client_session_lost");
            kernel_memory_available&=c.at("socket_memory_samples")==c.at("live_sessions");
            largest=std::max(largest,c.at("largest_queue_bytes").get<size_t>());queues+=budget_queued(c);
            client_largest_queues[i]=std::max(client_largest_queues[i],c.at("largest_queue_bytes").get<size_t>());
            tcp_receive+=c.at("tcp_receive_alloc_bytes").get<uint64_t>();tcp_send+=c.at("tcp_send_queued_bytes").get<uint64_t>();
            const auto memory=rss(peer->pid);total+=memory;client_peak=std::max(client_peak,memory);
            require(fd_count(peer->pid)<=16,"budget_client_fd_bound");
          }
          clients_peak=std::max(clients_peak,total);client_queue_peak=std::max(client_queue_peak,queues);
          tcp_receive_peak=std::max(tcp_receive_peak,tcp_receive);tcp_send_peak=std::max(tcp_send_peak,tcp_send);
          require(exit_peak<128*1024&&client_peak<128*1024,"budget_rss_bound");
          require(exit_peak-baseline_rss<32*1024+count*4*1024,"budget_exit_rss_growth");
          require(exit_fd_peak<=idle_fds+size_t(count),"budget_exit_fd_bound");samples++;
          next_sample=Clock::now()+std::chrono::milliseconds(100);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
      }
      require(samples>=3&&accepted*16384>=size_t(slow)*3*1024*1024,"budget_insufficient_load");
      for(int i=0;i<slow;i++){
        require(injected_by_client[i]*16384>=3*1024*1024,"budget_client_insufficient_load");
        require(client_largest_queues[i]>=queue_limit/2,"budget_client_pressure_not_observed");
      }
      require(largest>=queue_limit/2,"budget_pressure_not_observed");
      if(count>slow)require(probes>=3,"budget_healthy_progress_missing");
      const auto drops=server.budget_status().at("dropped_packets").get<uint64_t>()-drops_before;
      phases.push_back({{"cycle",cycle},{"phase",stage?"no-drain":"slow-drain"},{"slow_clients",slow},
        {"seconds",std::chrono::duration<double>(Clock::now()-start).count()},{"samples",samples},
        {"injected_flood_packets",accepted},{"drained_during_load",drained},{"exit_dropped_packets",drops},
        {"injected_flood_packets_by_client",injected_by_client},{"client_largest_queue_bytes",client_largest_queues},
        {"healthy_roundtrips",probes},{"worst_healthy_roundtrip_ms",worst_probe},
        {"exit_peak_rss_kib",exit_peak},{"client_peak_rss_kib",client_peak},{"clients_total_peak_rss_kib",clients_peak},
        {"sampled_largest_queue_bytes",largest},{"exit_queues_peak_bytes",exit_queue_peak},{"clients_queues_peak_bytes",client_queue_peak},
        {"exit_peak_fds",exit_fd_peak},{"kernel_socket_memory_available",kernel_memory_available},
        {"tls_tcp_receive_alloc_peak_bytes",kernel_memory_available?json(tcp_receive_peak):json(nullptr)},
        {"tls_tcp_send_queued_peak_bytes",kernel_memory_available?json(tcp_send_peak):json(nullptr)}});
      // Stop the producer and drain bounded queues. This verifies recovery from
      // a slow application without reconnecting or weakening health checks.
      const auto drain_end=Clock::now()+std::chrono::seconds(4);bool empty=false,quiet=false;
      while(Clock::now()<drain_end){
        for(int i=0;i<slow;i++)drained+=budget_drain(*peers[i],i);
        empty=budget_queued(server.budget_status().at("fixture_h2_budget"))==0;
        for(int i=0;i<slow;i++)empty&=budget_queued(peers[i]->budget_status().at("fixture_h2_budget"))==0;
        // Logical queues can be empty while TLS/TCP/socketpair still hold data.
        if(empty){std::this_thread::sleep_for(std::chrono::milliseconds(30));
          uint64_t more=0;for(int i=0;i<slow;i++)more+=budget_drain(*peers[i],i);
          if(!more){quiet=true;break;}
        }
      }
      require(empty&&quiet,"budget_drain_timeout");
      for(int i=0;i<count;i++)budget_probe(server,*peers[i],i);
    }
    // Repeated orderly disconnections, and an actual process death in cycle 2.
    const bool crash=cycle==1;
    for(auto& peer:peers){
      if(crash){require(kill(peer->pid,SIGKILL)==0,"budget_kill");peer.reset();}
      else{peer->command("{\"op\":\"uplink\",\"ready\":false}\n");peer->await_state("waiting_uplink");budget_wait_sessions(*peer,0);}
    }
    budget_wait_sessions(server,0);
    require(fd_count(server.pid)==idle_fds,"budget_fd_cleanup");
    const auto recovered_rss=rss(server.pid);const auto cleared=server.budget_status(false).at("fixture_h2_budget");
    require(cleared.at("created")==cleared.at("destroyed")&&budget_queued(cleared)==0,"budget_cleanup");
    if(cycle==2)require(recovered_rss-previous_recovered<8*1024,"budget_post_warmup_growth");
    previous_recovered=recovered_rss;
    recoveries.push_back({{"cycle",cycle},{"fault",crash?"SIGKILL":"uplink-off"},{"exit_rss_kib",recovered_rss},
      {"exit_fds",fd_count(server.pid)},{"sessions",cleared}});
    for(int i=0;i<count;i++){
      if(crash)peers[i]=std::make_unique<Child>(exe,configs[i].c_str());
      else peers[i]->command("{\"op\":\"uplink\",\"ready\":true}\n");
      peers[i]->await_state("ready");
    }
    budget_wait_sessions(server,count);for(int i=0;i<count;i++)budget_probe(server,*peers[i],i);
  }
  for(auto& peer:peers){peer->stop();}
  budget_wait_sessions(server,0);
  require(fd_count(server.pid)==idle_fds,"budget_final_fds");
  auto final=server.budget_status(false).at("fixture_h2_budget");server.stop();
  std::cout<<"H2_BUDGET_RESULT="<<json({{"schema",1},{"clients",count},{"mode",std::getenv("CVPN_TEST_H2_BUDGET")},
    {"duration_seconds",std::chrono::duration<double>(Clock::now()-began).count()},{"baseline_exit_rss_kib",baseline_rss},
    {"baseline_exit_fds",idle_fds},{"phases",phases},{"recoveries",recoveries},{"final_sessions",final},
    {"children_stopped",true},{"payload_verified",true}}).dump()<<"\n";
}
