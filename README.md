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
    
Analysing HTTP header!    
This packet's method is : GET    
Host:test.gilgil.net    
This packet is dropped!    
Analysing HTTP header!    
This packet's method is : GET    
Host:test.gilgil.net    
This packet is dropped!    
    
....
    
Analysing HTTP header!    
This packet's method is : GET    
Host:passport.tianya.cn    
This packet is accepted!    
Analysing HTTP header!    
This packet's method is : GET    
Host:test.gilgil.net    
This packet is dropped!    
Analysing HTTP header!    
This packet's method is : GET    
Host:rakuten.co.jp    
This packet is accepted!    
Analysing HTTP header!    
This packet's method is : GET    
Host:test.gilgil.net    
This packet is dropped!    
    
....
    
Analysing HTTP header!    
This packet doesn't uses get or post method!    
Analysing HTTP header!    
This packet's method is : GET    
Host:portal.korea.ac.kr    
This packet is accepted!    
Analysing HTTP header!    
This packet doesn't uses get or post method!    
Analysing HTTP header!    
This packet's method is : POST    
Host:portal.korea.ac.kr    
This packet is accepted!   
    
....
    
^C
