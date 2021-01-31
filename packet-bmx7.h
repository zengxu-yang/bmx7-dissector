/* packet-bmx7.h
 * Definitions for BMX7 packet disassembly structures and routines
 * By Ester Lopez <esterl@ac.upc.edu>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */


/** Frame types **/
typedef uint8_t  FRAME_TYPE_T;
#define FRAME_ISSHORT_BIT_SIZE   (1)
#define FRAME_RELEVANCE_BIT_SIZE  (1)
#define FRAME_TYPE_BIT_SIZE    ((8*sizeof(FRAME_TYPE_T)) - FRAME_ISSHORT_BIT_SIZE - FRAME_RELEVANCE_BIT_SIZE)
#define FRAME_TYPE_MASK        0xF8
#define FRAME_TYPE_ARRSZ       (FRAME_TYPE_MASK+1)
#define FRAME_HEADER_SHORT_LEN	2
#define	FRAME_HEADER_LONG_LEN	4

#define FRAME_TYPE_RSVD0        0
#define FRAME_TYPE_DESC_ADV	2
#define FRAME_TYPE_TEST_ADV     3
#define FRAME_TYPE_CONTENT_ADV	4
#define FRAME_TYPE_DEV_REQ      6
#define FRAME_TYPE_DEV_ADV      7
#define FRAME_TYPE_SIGNATURE_ADV     8
#define FRAME_TYPE_OGM_AGG_SQN_ADV     9
#define FRAME_TYPE_RP_ADV      11
#define FRAME_TYPE_HELLO_ADV    12
#define FRAME_TYPE_HELLO_REPLY_DHASH	13
#define FRAME_TYPE_DESC_REQ    14
#define FRAME_TYPE_IID_ADV    19
#define FRAME_TYPE_OGM_ADV     21
#define FRAME_TYPE_OGM_REQ     27
#define FRAME_TYPE_IID_REQ    28
#define FRAME_TYPE_DESC_REQ	29
#define FRAME_TYPE_CONTENT_REQ	30
#define FRAME_TYPE_NOP         31
#define FRAME_TYPE_MAX         (FRAME_TYPE_ARRSZ-1)
#define FRAME_TYPE_PROCESS_ALL    (255)
#define FRAME_TYPE_PROCESS_NONE   (254)

#define DESCRIPTION0_ID_NAME_LEN 32

/** TLV types **/
#define TLV_TYPE_MASK	FRAME_TYPE_MASK
#define BMX_DSC_TLV_CONTENT_HASH	0x00
#define BMX_DSC_TLV_NODE_PUBKEY		0x01
#define BMX_DSC_TLV_DSC_SIGNATURE       0x02
#define BMX_DSC_TLV_VERSION		0x03
#define BMX_DSC_TLV_RSA_LINK_PUBKEY	0x05
#define BMX_DSC_TLV_DHM_LINK_PUBKEY	0x06
#define BMX_DSC_TLV_SUPPORTS	0x09
#define BMX_DSC_TLV_TRUSTS	0x0A
#define BMX_DSC_TLV_METRIC      0x0D
#define BMX_DSC_TLV_LLIP	0x0E
#define BMX_DSC_TLV_HNA6       0x0F
#define BMX_DSC_TLV_JSON_SMS    0x10
#define BMX_DSC_TLV_TUN6            0x11
#define BMX_DSC_TLV_TUN4IN6_INGRESS 0x12
#define BMX_DSC_TLV_TUN6IN6_INGRESS 0x13
#define BMX_DSC_TLV_TUN4IN6_SRC     0x14
#define BMX_DSC_TLV_TUN6IN6_SRC     0x15
#define BMX_DSC_TLV_TUN4IN6_NET     0x16
#define BMX_DSC_TLV_TUN6IN6_NET     0x17

#define BMX_DSC_TLV_INFO	0x1C
#define BMX_DSC_TLV_MAX         (FRAME_TYPE_ARRSZ-1)
#define BMX_DSC_TLV_ARRSZ       (FRAME_TYPE_ARRSZ)

#define MSG_DEV_ADV_SZ	26
#define MSG_LINK_ADV_SZ	6
#define HASH_SHA1_LEN	20
#define HASH_SHA224_LEN	28
#define SIG112_LEN	14
#define MSG_DESC_ADV_SZ	HASH_SHA1_LEN+DESCRIPTION0_ID_NAME_LEN+18

/** OGM_ADV and ACK Frames **/
typedef guint16 AGGREG_SQN_T;
typedef guint16 OGM_MIX_T;
typedef guint16 OGM_SQN_T;
typedef guint16 IID_T;
typedef guint8 OGM_DEST_T;
#define HDR_OGM_ADV_SZ	2;
#define OGM_MIX_BIT_SIZE (sizeof (OGM_MIX_T) * 8)
#define OGM_IIDOFFST_BIT_SIZE (OGM_MIX_BIT_SIZE-(OGM_MANTISSA_BIT_SIZE+OGM_EXPONENT_BIT_SIZE))
#define OGM_IIDOFFST_MASK ((1<<OGM_IIDOFFST_BIT_SIZE)-1)
#define OGM_EXPONENT_BIT_POS (0)
#define OGM_MANTISSA_BIT_POS (0 + OGM_EXPONENT_BIT_SIZE)
#define OGM_IIDOFFST_BIT_POS (0 + OGM_MANTISSA_BIT_SIZE + OGM_EXPONENT_BIT_SIZE)
#define OGM_MANTISSA_BIT_SIZE  5
#define OGM_EXPONENT_BIT_SIZE  5
#define OGM_IID_RSVD_JUMP  (OGM_IIDOFFST_MASK)

/** METRICS **/
#define FM8_EXPONENT_BIT_SIZE  OGM_EXPONENT_BIT_SIZE
#define FM8_MANTISSA_BIT_SIZE  (8-FM8_EXPONENT_BIT_SIZE)
#define FM8_MANTISSA_MASK      ((1<<FM8_MANTISSA_BIT_SIZE)-1)
#define FM8_MANTISSA_MIN       (1)
struct float_u8 {
  union {

    struct {
      unsigned int exp_fmu8 : FM8_EXPONENT_BIT_SIZE;
      unsigned int mantissa_fmu8 : FM8_MANTISSA_BIT_SIZE;
    } __attribute__((packed)) f;
    guint8 u8;
  } val;
};

typedef struct float_u8 FMETRIC_U8_T;


