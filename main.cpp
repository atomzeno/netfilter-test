#include <stdio.h>
#include <ctype.h>
#include <iostream>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <libnet.h>
#include <stdint.h>
#include <string>
#include <string.h>
#include <set>
#include <algorithm>
#include <arpa/inet.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
using namespace std;
#define HOST_MAX_LENGTH 257
set <string> bansiteSet;

void dump(unsigned char* buf, int size) {
	int i;
	for (i = 0; i < size; i++) {
		if (i % 16 == 0)
			printf("\n");
		printf("%c", buf[i]);
	}
}


/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    //struct nfqnl_msg_packet_hw *hwph;
    //u_int32_t mark,ifi;
    //int ret;
    //unsigned char *data;

    ph = nfq_get_msg_packet_hdr(tb);
    if (ph) {
        id = ntohl(ph->packet_id);
        /*
        printf("hw_protocol=0x%04x hook=%u id=%u ",
            ntohs(ph->hw_protocol), ph->hook, id);
        */
        
    }
    /*
    hwph = nfq_get_packet_hw(tb);
    if (hwph) {
        int i, hlen = ntohs(hwph->hw_addrlen);
        
        printf("hw_src_addr=");
        for (i = 0; i < hlen-1; i++)
            printf("%02x:", hwph->hw_addr[i]);
        printf("%02x ", hwph->hw_addr[hlen-1]);
        
        
    }
    */
    /*
    mark = nfq_get_nfmark(tb);
    if (mark)
        printf("mark=%u ", mark);

    ifi = nfq_get_indev(tb);
    if (ifi)
        printf("indev=%u ", ifi);

    ifi = nfq_get_outdev(tb);
    if (ifi)
        printf("outdev=%u ", ifi);
    ifi = nfq_get_physindev(tb);
    if (ifi)
        printf("physindev=%u ", ifi);

    ifi = nfq_get_physoutdev(tb);
    if (ifi)
        printf("physoutdev=%u ", ifi);
    

    ret = nfq_get_payload(tb, &data);
    if (ret >= 0){
        printf("payload_len=%d ", ret);
        //dump(data, ret);
    }
    

    fputc('\n', stdout);
    */
    return id;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
          struct nfq_data *nfa, void *data)
{
    int i, j;
    u_int32_t id = print_pkt(nfa);
    u_char *packet;
    int packet_length;
    packet_length = nfq_get_payload(nfa, &packet);
    //printf("packet length : %d\n",packet_length);

    if(packet_length==0){
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }
    struct libnet_ipv4_hdr *packet_ip=(struct libnet_ipv4_hdr *)(packet);
    if(packet_ip->ip_p!=IPPROTO_TCP){//protocol isn't tcp
        //printf("this isn't tcp!\n");
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }
    int ip_header_length = ((int)packet_ip->ip_hl)*4;
    //printf("ip header length : %d\n",ip_header_length);

    struct libnet_tcp_hdr *packet_tcp=(struct libnet_tcp_hdr *)(packet + ip_header_length);
    if(packet_length==ip_header_length){
        //printf("packet_length==ip_header_length\n");
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }
    int tcp_header_length = ((int)packet_tcp->th_off)*4;
    //printf("tcp header length : %d\n",tcp_header_length);

    int packet_data_offset = ip_header_length + tcp_header_length;
    if(packet_length==packet_data_offset){
        //printf("packet_length==packet_data_offset\n");
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }
    /*
    printf("ip header length : %d\n",ip_header_length);
    printf("tcp header length : %d\n",tcp_header_length);
    printf("packet_data_offset : %d\n",packet_data_offset);
    dump(packet, packet_length);
    printf("\n\n");
    dump(packet+packet_data_offset, packet_length-packet_data_offset);
    printf("\n\n");
    */

    if(htons(packet_tcp->th_dport)!=80){
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }


    printf("Analysing HTTP header!\n");
    char *packet_http_data=(char *)(packet + packet_data_offset);
    packet_length-=packet_data_offset;
    
    /*
    if(packet_length > 70){
        for(i=0;i<16;i++){
            printf("%02x ",(char)packet_http_data[i]);
        }
        printf("\n");
        for(i=16;i<32;i++){
            printf("%02x ",(char)packet_http_data[i]);
        }
        printf("\n");
    }

    printf("start----------------------------------------------------\n");
    printf("%s\n",packet_http_data);
    printf("end------------------------------------------------------\n");
    */

    for(i=0;i<packet_length;i++){
        if(packet_http_data[i]!=' ' && packet_http_data[i]!='\n' && packet_http_data[i]!='\r'){
            break;
        }
    }
    char method_store[256];
    for(j=i;j<packet_length && j< i+7;j++){
        if(packet_http_data[j]==' ' || packet_http_data[j]=='\n' || packet_http_data[j]=='\r'){
            break;
        }
    }
    //printf("i : %d j : %d\n", i, j);
    if((j-i) > 4){
        printf("This packet doesn't uses get or post method!\n");
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }
    int imsi_cnt=0;
    for(i=i;i<j;i++){
        method_store[imsi_cnt++]=packet_http_data[i];
    }
    method_store[imsi_cnt]=0;
    printf("This packet's method is : %s\n",method_store);
    if((strcmp(method_store, "GET")!=0) && (strcmp(method_store, "POST")!=0)){
        printf("This packet doesn't uses get or post method!\n");
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }

    for(;i<packet_length;){
        char compare[9]="\r\nHost: ";
        for(i = i + 7;i<packet_length;i++){
            if(!strncmp(&packet_http_data[i-7], compare, 8)){
                break;
            }
        }
        //printf("\n%s\n",&packet_http_data[i-7]);
        //printf("\n%s\n",&packet_http_data[i+1]);
        
        //printf("\n\nI reached here! %d\n", i);
        
        //sleep(10);
        ++i;
        if(i>=packet_length){
            break;
        }
        //printf("\n\nI reached here! %d\n", i);
        char *packet_host_data=(char *)(packet_http_data+i);
        char hostname[HOST_MAX_LENGTH];
        for(j=0;j<256 && (i+j)<packet_length;j++){
            hostname[j]=packet_host_data[j];
            if(packet_host_data[j]=='\r'){
                hostname[j]=0;
                break;
            }
        }
        hostname[256]=0;
        //printf("------------------------------------------------------\n");
        //printf("!!!!Host:%s\n",hostname);
        //printf("------------------------------------------------------\n");
        string string_host_name;
        string_host_name.assign(hostname);
        //cout << "\nhost_name_string:" << string_host_name << "\n";
        printf("Host:%s\n", hostname);
        if(bansiteSet.find(string_host_name)!=bansiteSet.end()){
            printf("This packet is dropped!\n");
            return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
        }
        i = i + j;
    }
    printf("This packet is accepted!\n");
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
    if(argc!=2){
        printf("usage : ./netfilter-test test.gilgil.net\n");
        exit(1);
    }
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));
    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }
    string imsi;
    imsi.assign(argv[1]);
    cout << "input host : " << imsi << "\n";
    bansiteSet.insert(imsi);

    printf("binding this socket to queue '0'\n");
    qh = nfq_create_queue(h,  0, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    for (;;) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
            //printf("pkt received\n");
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        /* if your application is too slow to digest the packets that
         * are sent from kernel-space, the socket buffer that we use
         * to enqueue packets may fill up returning ENOBUFS. Depending
         * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
         * the doxygen documentation of this library on how to improve
         * this situation.
         */
        if (rv < 0 && errno == ENOBUFS) {
            printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

#ifdef INSANE
    /* normally, applications SHOULD NOT issue this command, since
     * it detaches other programs/sockets from AF_INET, too ! */
    printf("unbinding from AF_INET\n");
    nfq_unbind_pf(h, AF_INET);
#endif

    printf("closing library handle\n");
    nfq_close(h);

    exit(0);
}
