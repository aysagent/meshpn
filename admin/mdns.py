#!/usr/bin/env python3
"""Own one Avahi entry group; publish ONLY on the configured USB interface.
No hostname, DNS resolver, Avahi config or host network modifications.
"""
import dbus,json,re,socket,sys,time
assert len(sys.argv)==4
interface,name,address=sys.argv[1:]
assert re.fullmatch(r'[a-zA-Z0-9_.-]{1,15}',interface)
assert re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',name)
socket.inet_pton(socket.AF_INET,address)
bus=dbus.SystemBus()
server=dbus.Interface(bus.get_object('org.freedesktop.Avahi','/'),'org.freedesktop.Avahi.Server')
group=dbus.Interface(bus.get_object('org.freedesktop.Avahi',server.EntryGroupNew()),'org.freedesktop.Avahi.EntryGroup')
# AVAHI_PUBLISH_NO_REVERSE: preserve the existing board PTR record.
group.AddAddress(dbus.Int32(socket.if_nametoindex(interface)),dbus.Int32(0),dbus.UInt32(16),name+'.local',address)
group.Commit()
while True:
 state=int(group.GetState())
 if state in (3,4): raise SystemExit('mdns_collision_or_failure')
 print(json.dumps({'state':state,'hostname':name+'.local','interface':interface}),flush=True)
 time.sleep(5)
