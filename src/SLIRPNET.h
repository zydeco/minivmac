/*
    SLIRPNET.h

    Copyright (C) 2016-2020 Jesus A. Alvarez

    You can redistribute this file and/or modify it under the terms
    of version 2 of the GNU General Public License as published by
    the Free Software Foundation.  You should have received a copy
    of the license along with this file; see the file COPYING.

    This file is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    license for more details.
*/

/*
    SLIRP NETworking
    Implements networking over LocalTalk using slirp from BasiliskII
*/

#define SLIRP_dolog (dbglog_HAVE && 1)

#include "libslirp.h"

/* Slirp thread */
pthread_t slirp_thread;

/* buffers */
#define ETH_HLEN 14
static unsigned char tx_buffer[LT_TxBfMxSz];
static unsigned char rx_buffer[LT_TxBfMxSz];
size_t rx_buffer_size = 0;
pthread_mutex_t rx_mutex;
/* slirp deals in ethernet frames: add an ethernet header */
static unsigned char slirp_input_buf[ETH_HLEN + LT_TxBfMxSz] = "ddddddssssss\x08\x00";
static unsigned char slirp_output_buf[ETH_HLEN + LT_TxBfMxSz];

/* LLAP definitions */
ui3b lapAdrClient; // Guest address
#define lapAdrServer 0x80
#define lapAdrBroadcast 0xff
#define lapDDP 0x01
#define lapENQ 0x81
#define lapACK 0x82

/* DDP definitions */
#define ddpNBP 2 // Name Binding Protocol
#define ddpATP 3 // AppleTalk Transaction Protocol
#define ddpAEP 4 // AppleTalk Echo Protocol
#define ddpIP 22 // Internet Protocol

/* NBP definitions */
#define nbpBrRq 1
#define nbpLkUp 2
#define nbpLkUpReply 3
#define nbpFwdReq 4

/* ATP definitions */
#define atpTReq 0x40
#define atpTResp 0x80
#define atpTRel 0xc0
#define atpFunctionMask 0xc0
#define atpXO 0x20
#define atpEOM 0x10
#define atpSTS 0x80
#define atpTimeoutMask 0x07

/* MacIPGP definitions */
#define ipgpASSIGN 1
#define ipgpSERVER 3

/* IP definitions */
#include <ctl.h>

/* Socket Numbers */
#define sckNIS 2 // Names Information Socket
#define sckIP 72 // MacIP Socket

/* Own Prototypes */
void * slirp_receive_loop(void *arg);
LOCALPROC DDP_ReceivePacket(ui3p buf, ui4r bufsz);
LOCALPROC DDP_TransmitPacket(ui3b dst, ui3b dstSck, ui3b srcSck, ui3b ddpType, const unsigned char * ddpData, ui4r ddpDataLen);
LOCALPROC NBP_ReceivePacket(ui3b srcSck, ui3p buf, ui4r bufsz);
LOCALPROC NBP_LookUp(ui3b srcSck, ui3b nbpID, char *object, char *type, char *zone);
LOCALPROC ATP_ReceivePacket(ui3b srcSck, ui3b dstSck, ui3p buf, ui4r bufsz);


LOCALFUNC int InitLocalTalk(void)
{
    LT_PickStampNodeHint();
    
    /* Set up buffer */
    LT_TxBuffer = tx_buffer;
    
#ifndef _WIN32
    // Don't raise SIGPIPE, let errno be set to EPIPE
    struct sigaction sigpipe_sa;
    if (sigaction(SIGPIPE, NULL, &sigpipe_sa) == 0) {
        assert(sigpipe_sa.sa_handler == SIG_DFL || sigpipe_sa.sa_handler == SIG_IGN);
        sigfillset(&sigpipe_sa.sa_mask);
        sigpipe_sa.sa_flags = 0;
        sigpipe_sa.sa_handler = SIG_IGN;
        sigaction(SIGPIPE, &sigpipe_sa, NULL);
    }
#endif
    
    /* Initialize slirp */
    if (slirp_init() < 0) {
#if SLIRP_dolog
        dbglog_writeln("can't init slirp");
#endif
        return falseblnr;
    }
    
    mutex_init(rx_mutex);
    
    /* Start slirp thread */
    thread_init(slirp_thread, slirp_receive_loop, NULL);
    
    return trueblnr;
}

LOCALPROC UnInitLocalTalk(void)
{
    thread_cancel(slirp_thread);
    mutex_destroy(rx_mutex);
}

#if SLIRP_dolog
LOCALPROC LT_PrintPacket(blnr dirIn, ui3p buf, ui4r bufsz)
{
    char bytestr[4], line[64] = "";
    for(int i=0; i < bufsz; i+= 16) {
        if (i == 0) {
            if (dirIn) {
                strcat(line, "LT<-: ");
            } else {
                strcat(line, "LT->: ");
            }
        } else {
            sprintf(line, "%4x: ", i);
        }
        for(int j=i; j < i+16; j++) {
            if (j < bufsz) {
                sprintf(bytestr, "%02x", buf[j]);
                strcat(line, bytestr);
            } else {
                strcat(line, "  ");
            }
            if (j % 4 == 3) strcat(line, " ");
        }
        strcat(line, "| ");
        for(int j=i; j < i+16; j++) {
            sprintf(bytestr, "%c", j >= bufsz ? ' ' : isprint(buf[j]) ? buf[j] : '.');
            strcat(line, bytestr);
        }
        dbglog_writeln(line);
    }
}
#endif

GLOBALOSGLUPROC LT_TransmitPacket(void)
{
    if (LT_TxBuffSz <= 3) {
        return;
    }
#if SLIRP_dolog
    LT_PrintPacket(false, LT_TxBuffer, LT_TxBuffSz);
#endif
    
    ui3b dst = LT_TxBuffer[0];
    ui3b src = LT_TxBuffer[1];
    ui3b llap_type = LT_TxBuffer[2];
    lapAdrClient = src;
    
    if (dst != lapAdrServer && dst != lapAdrBroadcast) {
#if SLIRP_dolog
        dbglog_writeln("DDP packet not for server");
#endif
        return;
    }
    
    if (llap_type == lapDDP) {
        DDP_ReceivePacket(LT_TxBuffer + 3, LT_TxBuffSz - 3);
    }
}

GLOBALOSGLUPROC LT_ReceivePacket(void)
{
    mutex_lock(rx_mutex);
    if (rx_buffer_size) {
        LT_RxBuffer = rx_buffer;
        LT_RxBuffSz = rx_buffer_size;
        rx_buffer_size = 0;
#if SLIRP_dolog
        LT_PrintPacket(true, LT_RxBuffer, LT_RxBuffSz);
#endif
    }
    mutex_unlock(rx_mutex);
}

LOCALPROC DDP_ReceivePacket(ui3p buf, ui4r bufsz)
{
    if (bufsz < 5) {
#if SLIRP_dolog
        dbglog_writeln("DDP packet too small");
#endif
        return;
    }
    ui4b ddpLen = ((buf[0] & 0x03) << 8) + buf[1];
    if (ddpLen != bufsz) {
#if SLIRP_dolog
        dbglog_writeCStr("DDP packet with wrong size: ");
        dbglog_writeNum(ddpLen);
        dbglog_writeCStr(" != ");
        dbglog_writeNum(bufsz);
        dbglog_writeReturn();
#endif
        return;
    }
    ui3b dstSck = buf[2];
    ui3b srcSck = buf[3];
    ui3b ddpType = buf[4];
    ui3p ddpData = buf+5;
    
    switch(ddpType) {
        case ddpNBP:
            if (dstSck == sckNIS) {
                // NBP packets are always to NIS socket
                NBP_ReceivePacket(srcSck, ddpData, ddpLen - 5);
            }
            break;
        case ddpATP:
            ATP_ReceivePacket(srcSck, dstSck, ddpData, ddpLen - 5);
            break;
        case ddpIP:
            /* Assemble ethernet frame */
            memcpy(slirp_input_buf + ETH_HLEN, ddpData, bufsz - 5);
            slirp_input(slirp_input_buf, ETH_HLEN + bufsz - 5);
            break;
    }
}

LOCALPROC NBP_ReceivePacket(ui3b srcSck, ui3p buf, ui4r bufsz)
{
    if (bufsz < 2) {
#if SLIRP_dolog
        dbglog_writeln("NBP packet too small");
#endif
        return;
    }
    
    ui3b function = buf[0] >> 4;
    ui3b numTuples = buf[0] & 0x0f;
    if (function != nbpLkUp || numTuples != 1)
        return;
    ui3b nbpID = buf[1];
    char object[32], type[32], zone[32];
    
    // read the tuple
    ui3b objLen = buf[7];
    memcpy(object, buf + 8, objLen);
    object[objLen] = '\0';
    
    ui3b typeLen = buf[8 + objLen];
    memcpy(type, buf + 8 + objLen + 1, typeLen);
    type[typeLen] = '\0';
    
    ui3b zoneLen = buf[8 + objLen + 1 + typeLen];
    memcpy(zone, buf + 8 + objLen + 1 + typeLen + 1, zoneLen);
    zone[zoneLen] = '\0';
    
    NBP_LookUp(buf[5], nbpID, object, type, zone);
}

LOCALPROC NBP_LookUp(ui3b srcSck, ui3b nbpID, char *object, char *type, char *zone)
{
#if SLIRP_dolog
    dbglog_writeCStr("NBP look up for ");
    dbglog_writeCStr(object);
    dbglog_writeCStr(":");
    dbglog_writeCStr(type);
    dbglog_writeCStr(":");
    dbglog_writeCStr(zone);
    dbglog_writeReturn();
#endif
    if (strcmp(type, "IPGATEWAY") == 0) {
        // why yes, I am gateway
        struct in_addr in_gateway;
        in_gateway.s_addr = inet_addr(CTL_SPECIAL) | CTL_ALIAS;
        char *ipGateway = inet_ntoa(in_gateway);
        char buf[64] = "\x31.\0\0.\x48\x01.";
        strcat(buf+8, ipGateway);
        strcat(buf+8, "\x09IPGATEWAY\x01*");
        buf[1] = nbpID;
        buf[4] = lapAdrServer;
        buf[7] = strlen(ipGateway);
        DDP_TransmitPacket(lapAdrClient, srcSck, sckNIS, ddpNBP, (ui3p)buf, sizeof(buf)-1);
    }
}

LOCALPROC DDP_TransmitPacket(ui3b dst, ui3b dstSck, ui3b srcSck, ui3b ddpType, const unsigned char * ddpData, ui4r ddpDataLen)
{
    mutex_lock(rx_mutex);
    if (rx_buffer_size) {
        /* this shouldn't happen */
#if SLIRP_dolog
        dbglog_writeln("DDP_TransmitPacket: buffer full");
#endif
        mutex_unlock(rx_mutex);
        return;
    }
    
#if SLIRP_dolog
    dbglog_writeCStr("DDP_TransmitPacket: ");
    dbglog_writeNum(ddpDataLen);
    dbglog_writeCStr(" data bytes");
    dbglog_writeReturn();
#endif
    ui3p buf = rx_buffer;
    ui4r ddpLen = ddpDataLen + 5;
    buf[0] = dst;
    buf[1] = lapAdrServer;
    buf[2] = lapDDP;
    buf[3] = (ddpLen & 0xFF00) >> 8;
    buf[4] = ddpLen & 0xFF;
    buf[5] = dstSck;
    buf[6] = srcSck;
    buf[7] = ddpType;
    memcpy(buf+8, ddpData, ddpDataLen);
    rx_buffer_size = ddpLen + 3;
    mutex_unlock(rx_mutex);
}

LOCALPROC ATP_ReceivePacket(ui3b srcSck, ui3b dstSck, ui3p buf, ui4r bufsz)
{
    if (bufsz < 8) {
#if SLIRP_dolog
        dbglog_writeln("ATP packet too small");
#endif
        return;
    }
    
    ui3b ctl = buf[0]; // control information
    ui3p atp_data = buf+8;
    ui4r atp_len = bufsz - 8;
    
    if (ctl == atpTReq && dstSck == sckIP && atp_len >= 4) {
        ui5b ipgpCode = ntohl(*(ui5p)atp_data);
        if (ipgpCode == ipgpASSIGN || ipgpCode == ipgpSERVER) {
            ui3b sndbuf[8 + 4 + 32]; // ATP header + IPGP code + IPGP data
            sndbuf[0] = atpTResp | atpEOM;
            sndbuf[1] = 0; // sequence number
            sndbuf[2] = buf[2]; // transaction ID (high)
            sndbuf[3] = buf[3]; // transaction ID (low)
            *(ui5p)(sndbuf+8) = htonl(ipgpCode); // MacIPGP response code
            inet_aton(CTL_LOCAL, (struct in_addr*)(sndbuf+12)); // assigned IP address
            // name server address
            inet_aton(CTL_SPECIAL, (struct in_addr*)(sndbuf+16));
            sndbuf[19] = CTL_DNS;
            memset(sndbuf+20, 0, 24);
            DDP_TransmitPacket(lapAdrClient, srcSck, dstSck, ddpATP, sndbuf, sizeof(sndbuf));
        }
#if SLIRP_dolog
    } else {
        dbglog_writeln("unhandled ATP packet");
#endif
    }
}

void * slirp_receive_loop(void *arg)
{
    for(;;) {
        // Wait for packets to arrive
        fd_set rfds, wfds, xfds;
        int nfds;
        struct timeval tv;
        nfds = -1;
        FD_ZERO(&rfds);
        FD_ZERO(&wfds);
        FD_ZERO(&xfds);
        int timeout = slirp_select_fill(&nfds, &rfds, &wfds, &xfds);
        tv.tv_sec = 0;
        tv.tv_usec = timeout;
        if (select(nfds + 1, &rfds, &wfds, &xfds, &tv) >= 0) {
            slirp_select_poll(&rfds, &wfds, &xfds);
        }
    }
    return NULL;
}

int slirp_can_output()
{
    int can_output = 1;
    mutex_lock(rx_mutex);
    if (LT_RxBuffer || rx_buffer_size) {
        can_output = 0;
    }
    mutex_unlock(rx_mutex);
#if SLIRP_dolog
    if (!can_output) {
        dbglog_writeln("slirp can not output - buffer full");
    }
#endif
    return can_output;
}

void slirp_output(const uint8 *pkt, int pkt_len)
{
#if SLIRP_dolog
    dbglog_writeCStr("slirp_output frame: ");
    dbglog_writeNum(pkt_len);
    dbglog_writeCStr(" bytes");
    dbglog_writeReturn();
#endif
    
    // remove ethernet frame header
    const uint8 *ip_packet = pkt + ETH_HLEN;
    int ip_len = pkt_len - ETH_HLEN;
    DDP_TransmitPacket(lapAdrClient, sckIP, lapDDP, ddpIP, ip_packet, ip_len);
}
