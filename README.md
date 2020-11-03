# netfilter-test
    
after typing

sudo iptables -F
sudo iptables -A OUTPUT -j NFQUEUE --queue-num 0
sudo iptables -A INPUT -j NFQUEUE --queue-num 0

usage example 1 : ./netfilter-test test.gilgil.net    
usage example 2 : ./netfilter-test portal.korea.ac.kr    
    
sudo qmake    
sudo make    
sudo ./netfilter-test test.gilgil.net    
    
# example of execution    
    
./netfilter-test test.gilgil.net    
        
opening library handle    
unbinding existing nf_queue handler for AF_INET (if any)    
binding nfnetlink_queue as nf_queue handler for AF_INET    
input host : test.gilgil.net    
binding this socket to queue '0'    
setting copy_packet mode    
    
hw_protocol=0x0800 hook=3 id=1 outdev=2 payload_len=61    
hw_protocol=0x0800 hook=1 id=2 hw_src_addr=b8:55:10:e0:10:50 indev=2 payload_len=55    
hw_protocol=0x0800 hook=3 id=3 outdev=2 payload_len=52    
    
....
    
hw_protocol=0x0800 hook=3 id=63 outdev=2 payload_len=523 
Analysing HTTP header!
Host:timebit.sg
 This is accepted!
    
....
    
hw_protocol=0x0800 hook=3 id=89 outdev=2 payload_len=540    
Analysing HTTP header!    
Host:test.gilgil.net    
 This is dropped!    
    
....
    
^C
