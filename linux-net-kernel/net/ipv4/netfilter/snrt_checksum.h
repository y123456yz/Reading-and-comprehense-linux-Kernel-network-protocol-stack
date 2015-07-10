/* $Id: checksum.h,v 1.1 2010/05/10 10:08:04 zhengjiangyong Exp $ */
/*
** Copyright (C) 2000,2001 Christopher Cramer <cec@ee.duke.edu>
** Snort is Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
**
** Copyright (C) 2002 Sourcefire,Inc 
** Marc Norton <mnorton@sourcefire.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
**
**
** 7/2002 Marc Norton - added inline/optimized checksum routines
**                      these handle all hi/low endian issues
** 8/2002 Marc Norton - removed old checksum code and prototype
**
*/

#ifndef __CHECKSUM_H__
#define __CHECKSUM_H__


/* define checksum error flags */
#define CSE_IP    0x01
#define CSE_TCP   0x02
#define CSE_UDP   0x04
#define CSE_ICMP  0x08
#define CSE_IGMP  0x10

/*
*  checksum IP  - header=20+ bytes
*
*  w - short words of data
*  blen - byte length
* 
*/
static inline unsigned short in_chksum_ip(  unsigned short * w, int blen )
{
   unsigned int cksum;

   /* IP must be >= 20 bytes */
   cksum  = w[0];
   cksum += w[1];
   cksum += w[2];
   cksum += w[3];
   cksum += w[4];
   cksum += w[5];
   cksum += w[6];
   cksum += w[7];
   cksum += w[8];
   cksum += w[9];

   blen  -= 20;
   w     += 10;

   while( blen ) /* IP-hdr must be an integral number of 4 byte words */
   {
     cksum += w[0];
     cksum += w[1];
     w     += 2;
     blen  -= 4;
   }

   cksum  = (cksum >> 16) + (cksum & 0x0000ffff);
   cksum += (cksum >> 16);
 
   return (unsigned short) (~cksum);
}


/*
*  checksum tcp
*
*  h    - pseudo header - 12 bytes
*  d    - tcp hdr + payload
*  dlen - length of tcp hdr + payload in bytes
*
*/
static inline unsigned short in_chksum_tcp(  unsigned short *h, unsigned short * d, int dlen )
{
   unsigned int cksum;
   unsigned short answer=0;

   /* PseudoHeader must have 12 bytes */
   cksum  = h[0];
   cksum += h[1];
   cksum += h[2];
   cksum += h[3];
   cksum += h[4];
   cksum += h[5];

   /* TCP hdr must have 20 hdr bytes */
   cksum += d[0];
   cksum += d[1];
   cksum += d[2];
   cksum += d[3];
   cksum += d[4];
   cksum += d[5];
   cksum += d[6];
   cksum += d[7];
   cksum += d[8];
   cksum += d[9];

   dlen  -= 20; /* bytes   */
   d     += 10; /* short's */ 

   while(dlen >=32)
   {
     cksum += d[0];
     cksum += d[1];
     cksum += d[2];
     cksum += d[3];
     cksum += d[4];
     cksum += d[5];
     cksum += d[6];
     cksum += d[7];
     cksum += d[8];
     cksum += d[9];
     cksum += d[10];
     cksum += d[11];
     cksum += d[12];
     cksum += d[13];
     cksum += d[14];
     cksum += d[15];
     d     += 16;
     dlen  -= 32;
   }

   while(dlen >=8)  
   {
     cksum += d[0];
     cksum += d[1];
     cksum += d[2];
     cksum += d[3];
     d     += 4;   
     dlen  -= 8;
   }

   while(dlen > 1)
   {
     cksum += *d++;
     dlen  -= 2;
   }

   if( dlen == 1 ) 
   { 
    /* printf("new checksum odd byte-packet\n"); */
    *(unsigned char*)(&answer) = (*(unsigned char*)d);

    /* cksum += (u_int16_t) (*(u_int8_t*)d); */
     
     cksum += answer;
   }
   
   cksum  = (cksum >> 16) + (cksum & 0x0000ffff);
   cksum += (cksum >> 16);
 
   return (unsigned short)(~cksum);
}

/*
*  checksum udp
*
*  h    - pseudo header - 12 bytes
*  d    - udp hdr + payload
*  dlen - length of payload in bytes
*

首先，查看了Linux 2.6内核中的校验算法，使用汇编语言编写的，显然效率要高些。代码如下：
unsigned short ip_fast_csum(unsigned char * iph,
unsigned int ihl) 在外出ip_rcv中已经校验过了，为什么还要校验，还有这个校验为什么不是判断两个值是否相等，就是和接收的校验码相等

*/
static inline unsigned short in_chksum_udp(  unsigned short *h, unsigned short * d, int dlen )
{
   unsigned int cksum;
   unsigned short answer=0;

   /* PseudoHeader must have  12 bytes */
   cksum  = h[0];
   cksum += h[1];
   cksum += h[2];
   cksum += h[3];
   cksum += h[4];
   cksum += h[5];

   /* UDP must have 8 hdr bytes */
   cksum += d[0];
   cksum += d[1];
   cksum += d[2];
   cksum += d[3];

   dlen  -= 8; /* bytes   */
   d     += 4; /* short's */ 

   while(dlen >=32) 
   {
     cksum += d[0];
     cksum += d[1];
     cksum += d[2];
     cksum += d[3];
     cksum += d[4];
     cksum += d[5];
     cksum += d[6];
     cksum += d[7];
     cksum += d[8];
     cksum += d[9];
     cksum += d[10];
     cksum += d[11];
     cksum += d[12];
     cksum += d[13];
     cksum += d[14];
     cksum += d[15];
     d     += 16;
     dlen  -= 32;
   }

   while(dlen >=8)
   {
     cksum += d[0];
     cksum += d[1];
     cksum += d[2];
     cksum += d[3];
     d     += 4;   
     dlen  -= 8;
   }

   while(dlen > 1) 
   {
     cksum += *d++;
     dlen  -= 2;
   }

   if( dlen == 1 ) 
   { 
     *(unsigned char*)(&answer) = (*(unsigned char*)d);
     cksum += answer;
   }
   
   cksum  = (cksum >> 16) + (cksum & 0x0000ffff);
   cksum += (cksum >> 16);
 
   return (unsigned short)(~cksum);
}

/*
*  checksum icmp
*/
static inline unsigned short in_chksum_icmp( unsigned short * w, int blen )
{
  unsigned  short answer=0;
  unsigned int cksum = 0;

  while(blen >=32) 
  {
     cksum += w[0];
     cksum += w[1];
     cksum += w[2];
     cksum += w[3];
     cksum += w[4];
     cksum += w[5];
     cksum += w[6];
     cksum += w[7];
     cksum += w[8];
     cksum += w[9];
     cksum += w[10];
     cksum += w[11];
     cksum += w[12];
     cksum += w[13];
     cksum += w[14];
     cksum += w[15];
     w     += 16;
     blen  -= 32;
  }

  while(blen >=8) 
  {
     cksum += w[0];
     cksum += w[1];
     cksum += w[2];
     cksum += w[3];
     w     += 4;
     blen  -= 8;
  }

  while(blen > 1) 
  {
     cksum += *w++;
     blen  -= 2;
  }

  if( blen == 1 ) 
  {
    *(unsigned char*)(&answer) = (*(unsigned char*)w);
    cksum += answer;
  }

  cksum  = (cksum >> 16) + (cksum & 0x0000ffff);
  cksum += (cksum >> 16);


  return (unsigned short)(~cksum);
}

#endif /* __CHECKSUM_H__ */
