/* packet-bmx7.c
 * Routines for BMX7 protocol packet disassembly
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>
#include <arpa/inet.h>
#include <epan/packet.h>
#include "packet-bmx7.h"

//TODO delete
#include <stdio.h>

#include "packet-bmx7-hf.c"

#define DEBUG

#ifdef DEBUG
#define my_print(...) g_print(__VA_ARGS__)
#else
#define my_print(...)
#endif

#define PROTO_TAG_BMX    "BMX7"
static const value_string bmx_frame_types[] =
  {
   { FRAME_TYPE_RSVD0, "RSVD frame" },
   { FRAME_TYPE_CONTENT_ADV, "Content advertisement"},
   { FRAME_TYPE_TEST_ADV, "Test advertisement frame" },
   { FRAME_TYPE_HELLO_ADV, "Hello advertisement" },
   { FRAME_TYPE_HELLO_REPLY_DHASH, "Hello reply DHash"},
   { FRAME_TYPE_DEV_REQ, "Device request" },
   { FRAME_TYPE_DEV_ADV, "Device advertisement" },
   { FRAME_TYPE_SIGNATURE_ADV, "Signature advertisement" },
   { FRAME_TYPE_OGM_AGG_SQN_ADV, "Ogm Aggregated SQN advertisement" },
   { FRAME_TYPE_RP_ADV, "Response advertisement" },
   { FRAME_TYPE_DESC_REQ, "Description request" },
   { FRAME_TYPE_DESC_ADV, "Description advertisement" },
   { FRAME_TYPE_HASH_REQ, "Hash request" },
   { FRAME_TYPE_HASH_ADV, "Hash advertisement" },
   { FRAME_TYPE_OGM_ADV, "Originator message advertisement" },
   { FRAME_TYPE_OGM_ACK, "Originator message acknowledgment" },
   { FRAME_TYPE_NOP, "No operation" },
   { FRAME_TYPE_CONTENT_REQ, "Content request"},
   { 0, NULL }
  };

static const value_string bmx_tlv_types[] =
  {				     
   { BMX_DSC_TLV_CONTENT_HASH, "Content Hash"},
   { BMX_DSC_TLV_NODE_PUBKEY, "Node Pubkey"},
   { BMX_DSC_TLV_DSC_SIGNATURE, "Desc Signature"},
   { BMX_DSC_TLV_VERSION, "Version"},
   //   { BMX_DSC_TLV_UHNA4, "HNA4 TLV"},
   { BMX_DSC_TLV_RSA_LINK_PUBKEY, "RSA Link Pubkey"},
   { BMX_DSC_TLV_DHM_LINK_PUBKEY, "DHM Link Pubkey"},
   { BMX_DSC_TLV_METRIC, "Metric"},
   { BMX_DSC_TLV_LLIP, "Link-local Address"},
   { BMX_DSC_TLV_HNA6, "HNA6 TLV"},
   { BMX_DSC_TLV_TUN6, "TUN6 TLV"},
   { BMX_DSC_TLV_TUN4IN6_INGRESS, "TUN4IN6_INGRESS_ADV TLV"},
   { BMX_DSC_TLV_TUN6IN6_INGRESS, "TUN6IN6_INGRESS_ADV TLV"},
   { BMX_DSC_TLV_TUN4IN6_SRC, "TUN4IN6_SRC_ADV TLV"},
   { BMX_DSC_TLV_TUN6IN6_SRC, "TUN6IN6_SRC_ADV TLV"},
   { BMX_DSC_TLV_TUN4IN6_NET, "TUN4IN6_NET_ADV TLV"},
   { BMX_DSC_TLV_TUN6IN6_NET, "TUN6IN6_NET_ADV TLV"},
   { BMX_DSC_TLV_INFO, "Info"},
   { BMX_DSC_TLV_JSON_SMS, "JSON_SMS TLV"},
   { 0, NULL }
  };

static int proto_bmx7 = -1;

static int hf_bmx7_version = -1;
static int hf_bmx7_keyhash = -1;
static int hf_bmx7_tx_iid = -1;
static int hf_bmx7_link_sqn = -1;
static int hf_bmx7_pkt_sqn = -1;
static int hf_bmx7_local_id = -1;
static int hf_bmx7_dev_idx = -1;
static int hf_bmx7_frame_is_short = -1;
static int hf_bmx7_frame_is_relevant = -1;
static int hf_bmx7_frame_length8 = -1;
static int hf_bmx7_frame_length16 = -1;
static int hf_bmx7_frame_type = -1;
static int hf_bmx7_hello_sqn = -1;
static int hf_bmx7_tlv_type = -1;

/* Packet header */
static gint ett_bmx7 = -1;
static gint ett_bmx7_version = -1;
static gint ett_bmx7_keyhash = -1;
static gint ett_bmx7_tx_iid = -1;
static gint ett_bmx7_link_sqn = -1;
static gint ett_bmx7_pkt_sqn = -1;
static gint ett_bmx7_local_id = -1;
static gint ett_bmx7_dev_idx = -1;
static gint ett_bmx7_frame_header = -1;
static gint ett_bmx7_message = -1;

/* HELLO_ADV frame */
static gint ett_bmx7_hello_adv = -1;

/* RP_ADV frame */
static gint ett_bmx7_rp_adv = -1;

/* CONTENT_ADV frame */
static gint ett_bmx7_content_adv = -1;

/* CONTENT_REQ frame */
static gint ett_bmx7_content_req = -1;

/* SIGNATURE_ADV frame */
static gint ett_bmx7_signature_adv = -1;

/* OGM_AGG_SQN_ADV frame */
static gint ett_bmx7_ogm_agg_sqn_adv = -1;
static gint ett_bmx7_link = -1;

/* DEV_REQ frame */
static gint ett_bmx7_dev_req = -1;

/* DEV_ADV frame */
static gint ett_bmx7_dev_adv = -1;

/* HASH_REQ frame */
static gint ett_bmx7_hash_req = -1;

/* HASH_ADV frame */
static gint ett_bmx7_hash_adv = -1;

/* DESC_REQ frame */
static gint ett_bmx7_desc_req = -1;

/* DESC_ADV frame */
static gint ett_bmx7_desc_adv = -1;

/* OGM_ADV frame */
static gint ett_bmx7_ogm_adv = -1;

/* OGM_ACK frame */
static gint ett_bmx7_ogm_ack = -1;

/* TLVs */
static gint ett_bmx7_tlv_content_hash = -1;
static gint ett_bmx7_tlv_dsc_signature = -1;
static gint ett_bmx7_tlv_version = -1;
static gint ett_bmx7_tlv_rsa_link_pubkey = -1;
static gint ett_bmx7_tlv_dhm_link_pubkey = -1;
static gint ett_bmx7_tlv_metric = -1;
static gint ett_bmx7_tlv_llip = -1;
static gint ett_bmx7_tlv_uhna4 = -1;
static gint ett_bmx7_tlv_hna6 = -1;
static gint ett_bmx7_tlv_tun6 = -1;
static gint ett_bmx7_tlv_tun4in6_ingress = -1;
static gint ett_bmx7_tlv_tun6in6_ingress = -1;
static gint ett_bmx7_tlv_tun4in6_src = -1;
static gint ett_bmx7_tlv_tun6in6_src = -1;
static gint ett_bmx7_tlv_tun4in6_net = -1;
static gint ett_bmx7_tlv_tun6in6_net = -1;
static gint ett_bmx7_tlv_info = -1;
static gint ett_bmx7_tlv_json_sms = -1;
static gint ett_bmx7_tlv_header = -1;

//Dissects a hello message
static int
dissect_hello_adv(tvbuff_t *tvb, proto_item *ti, int offset, int version){
  guint8 reserved;
  guint16 sqn;
    
  sqn = tvb_get_ntohs(tvb, offset);
  proto_item_append_text(ti, "  sequence number: %u", sqn);
  offset +=2;
  if(version == 13){
    reserved = tvb_get_guint8(tvb, offset);
    proto_item_append_text(ti, ", reserved: 0x%x", reserved);
    proto_item_set_len(ti, 3);
    offset++;
  }
  return offset;
}

//Dissects a signature adv message
static int
dissect_signature_adv(tvbuff_t *tvb, proto_tree *tree, int offset, int end){

  guint32 dest_id;
  gchar* hash;
  
  proto_tree_add_item(tree, hf_bmx7_desc_sqn, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;
  proto_tree_add_item(tree, hf_bmx7_burst_sqn, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset +=4;
  dest_id = tvb_get_ntohl(tvb, offset);
  proto_tree_add_item(tree, hf_bmx7_dev_idx, tvb, offset, 1, ENC_NA);
  offset++;
  if (offset < end){
    proto_tree_add_item(tree, hf_bmx7_signature_type, tvb, offset, 1, ENC_NA);
    offset++;
    hash = tvb_bytes_to_str(NULL, tvb, offset, SIG112_LEN);
    proto_tree_add_string(tree, hf_bmx7_signature, tvb, offset, SIG112_LEN, hash);
    return offset+14;
  }else
    return offset;
}

//Dissects link advertisment messages
static int
dissect_link_adv(tvbuff_t *tvb, proto_tree *tree, int offset, int end){
  guint8 tx_dev, peer_dev;
  guint16 dev_sqn;
  guint32 peer_id;
  proto_tree *links, *link_tree;
  proto_item *ti;
    
  dev_sqn = tvb_get_ntohs(tvb, offset);
  ti = proto_tree_add_item(tree, hf_bmx7_device_sequence_number, tvb, offset, 2, ENC_BIG_ENDIAN);
  links = proto_item_add_subtree(ti, ett_bmx7_message);
  offset +=2;
  int i =1;
  while(end > offset){
    ti = proto_tree_add_item(links, hf_bmx7_link, tvb, offset, 6, ENC_BIG_ENDIAN);
    link_tree = proto_item_add_subtree(ti, ett_bmx7_link);
    tx_dev = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(link_tree, hf_bmx7_transmitter_device_id, tvb, offset, 1, ENC_NA);
    offset ++;
    peer_dev = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(link_tree, hf_bmx7_peer_device_id, tvb, offset, 1, ENC_NA);
    offset ++;
    peer_id = tvb_get_ntohl(tvb, offset);
    proto_tree_add_item(link_tree, hf_bmx7_peer_local_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_item_append_text(ti, "    to 0x%x:dev%u", peer_id, peer_dev);
    offset +=4;
    i++;
  }
  return offset;
}

//Dissects a device request message
static int
dissect_dev_req(tvbuff_t *tvb, proto_tree *tree, int offset){
  guint32 dst_id = tvb_get_ntohl(tvb, offset);
  proto_tree_add_item(tree, hf_bmx7_destination_local_id, tvb, offset, 4, ENC_BIG_ENDIAN);
  return offset+4;
}

//Dissects device advertisement messages
static int
dissect_dev_adv(tvbuff_t *tvb, proto_tree *tree, int offset, int end){
  guint8 dev_idx, channel;
  guint16 dev_sqn;
  guint64 mac;
  FMETRIC_U8_T tx_min, tx_max;
  char str[INET6_ADDRSTRLEN];
  struct e_in6_addr ipv6;
  int i;
  proto_tree *devices, *device_tree;
  proto_item *ti;
    
  dev_sqn = tvb_get_ntohs(tvb, offset);
  ti = proto_tree_add_item(tree, hf_bmx7_device_sequence_number, tvb, offset, 2, ENC_BIG_ENDIAN);
  devices = proto_item_add_subtree(ti, ett_bmx7_message);
  offset+=2;
  i =1;
  while(offset < end){
    ti = proto_tree_add_item(devices, hf_bmx7_device, tvb, offset, 6, ENC_BIG_ENDIAN);
    device_tree = proto_item_add_subtree(ti, ett_bmx7_link);
    dev_idx = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(device_tree, hf_bmx7_device_index, tvb, offset, 1, ENC_NA);
    offset++;
    channel = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(device_tree, hf_bmx7_channel, tvb, offset, 1, ENC_NA);
    offset++;
    tx_min.val.u8 = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(device_tree, hf_bmx7_transmitter_min_bitrate, tvb, offset, 1, ENC_NA);
    offset++;
    tx_max.val.u8 = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(device_tree, hf_bmx7_transmitter_max_bitrate, tvb, offset, 1, ENC_NA);
    offset++;
    tvb_get_ipv6(tvb, offset, &ipv6);
    inet_ntop(AF_INET6, &ipv6, str, INET6_ADDRSTRLEN);
    proto_tree_add_item(device_tree, hf_bmx7_local_ipv6, tvb, offset, 16, ENC_BIG_ENDIAN);
    proto_item_append_text(ti, "    ip address: %s", str);
    offset += 16;
    mac = tvb_get_ntoh48(tvb, offset);
    proto_tree_add_item(device_tree, hf_bmx7_mac_address, tvb, offset, 6, ENC_BIG_ENDIAN);
    offset +=6;
    i++;
  }
  return offset;
}

static int
dissect_hash_req(tvbuff_t *tvb, proto_tree *tree, int offset, int end){
  guint32 dst_id;
  int i;
  proto_item *ti;
  proto_tree *requests;
    
  dst_id = tvb_get_ntohl(tvb, offset);
  ti = proto_tree_add_item(tree, hf_bmx7_destination_local_id, tvb, offset, 4, ENC_BIG_ENDIAN);
  requests = proto_item_add_subtree(ti, ett_bmx7_message);
  offset += 4;
  i =1;
  while(offset<end){
    proto_tree_add_item(requests, hf_bmx7_request, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    i++;
  }
  return offset;
}

static int
dissect_hash_adv(tvbuff_t *tvb, proto_item *ti, int offset){
  guint16 transmitter_iid;
  proto_tree *tree;
  gchar *hash;
    
  tree = proto_item_add_subtree(ti, ett_bmx7_message);
  transmitter_iid = tvb_get_ntohs(tvb, offset);
  proto_tree_add_item(tree, hf_bmx7_transmitteriid4x, tvb, offset, 2, ENC_BIG_ENDIAN);
  proto_item_append_text(ti, "    from %u", transmitter_iid);
  offset +=2;
  hash = tvb_bytes_to_str(NULL, tvb, offset, HASH_SHA1_LEN);
  proto_tree_add_item(tree, hf_bmx7_description_hash, tvb, offset, HASH_SHA1_LEN, ENC_BIG_ENDIAN);
  proto_item_set_len(ti, 2 + HASH_SHA1_LEN);
  offset += HASH_SHA1_LEN;
  return offset;
}

static int
dissect_bmx7_tlv(tvbuff_t *tvb, proto_item *tlv_item, int offset){
  guint8 type, is_short, etype;
  guint16 length;
  int bit_offset, num, header_length;
  proto_tree *tlv, *tlv_header;
  proto_item *ti, *th_item, *tlv_v_item, *tlv_s_item, *tlv_c_item;
    
  //Add the proper subtree:
  type = (tvb_get_guint8(tvb, offset) & 0xf8) >> 3;
  proto_item_append_text(tlv_item, val_to_str(type, bmx_tlv_types, 
					      "Unknown tlv type: %u"));
  switch(type) {
  case BMX_DSC_TLV_CONTENT_HASH:
    tlv = proto_item_add_subtree(tlv_item, ett_bmx7_tlv_content_hash);
    break;
  case BMX_DSC_TLV_DSC_SIGNATURE:
    tlv = proto_item_add_subtree(tlv_item, ett_bmx7_tlv_dsc_signature);
    break;
  case BMX_DSC_TLV_VERSION:
    tlv = proto_item_add_subtree(tlv_item, ett_bmx7_tlv_version);
    break;
  case BMX_DSC_TLV_RSA_LINK_PUBKEY:
    tlv = proto_item_add_subtree(tlv_item, ett_bmx7_tlv_rsa_link_pubkey);
    break;
  case BMX_DSC_TLV_DHM_LINK_PUBKEY:
    tlv = proto_item_add_subtree(tlv_item, ett_bmx7_tlv_dhm_link_pubkey);
    break;
  case BMX_DSC_TLV_METRIC:
    tlv = proto_item_add_subtree(tlv_item, ett_bmx7_tlv_metric);
    break;
  case BMX_DSC_TLV_LLIP:
    tlv = proto_item_add_subtree(tlv_item, ett_bmx7_tlv_llip);
    break;
  case BMX_DSC_TLV_HNA6:
    tlv = proto_item_add_subtree(tlv_item, ett_bmx7_tlv_hna6);
    break;
  case BMX_DSC_TLV_TUN6:
    tlv = proto_item_add_subtree(tlv_item, ett_bmx7_tlv_tun6);
    break;
  case BMX_DSC_TLV_TUN4IN6_INGRESS:
    tlv = proto_item_add_subtree(tlv_item, ett_bmx7_tlv_tun4in6_ingress);
    break;
  case BMX_DSC_TLV_TUN6IN6_INGRESS:
    tlv = proto_item_add_subtree(tlv_item, ett_bmx7_tlv_tun6in6_ingress);
    break;
  case BMX_DSC_TLV_TUN4IN6_SRC:
    tlv = proto_item_add_subtree(tlv_item, ett_bmx7_tlv_tun4in6_src);
    break;
  case BMX_DSC_TLV_TUN6IN6_SRC:
    tlv = proto_item_add_subtree(tlv_item, ett_bmx7_tlv_tun6in6_src);
    break;
  case BMX_DSC_TLV_TUN4IN6_NET:
    tlv = proto_item_add_subtree(tlv_item, ett_bmx7_tlv_tun4in6_net);
    break;
  case BMX_DSC_TLV_TUN6IN6_NET:
    tlv = proto_item_add_subtree(tlv_item, ett_bmx7_tlv_tun6in6_net);
    break;
  case BMX_DSC_TLV_INFO:
    tlv = proto_item_add_subtree(tlv_item, ett_bmx7_tlv_info);
    break;
  case BMX_DSC_TLV_JSON_SMS:
    tlv = proto_item_add_subtree(tlv_item, ett_bmx7_tlv_json_sms);
    break;
  default:
    //TODO new ett
    tlv = proto_item_add_subtree(tlv_item, ett_bmx7_hello_adv);
    break;
  }
    
  //TLV header
  th_item = proto_tree_add_item(tlv, hf_bmx7_tlv_header, tvb, offset, -1, ENC_NA);
  tlv_header= proto_item_add_subtree(th_item, ett_bmx7_tlv_header);
  bit_offset = offset*8;
  //type
  proto_tree_add_item(tlv_header, hf_bmx7_tlv_type, tvb, offset, 1, 
		      ENC_NA);
  //length
  length = tvb_get_ntohs(tvb, offset) & 0x7ff;
  my_print("Length is %d\n", length);
  proto_tree_add_bits_item(tlv_header, hf_bmx7_frame_length16, tvb, bit_offset+5, 11, ENC_BIG_ENDIAN);
  offset+=2;
  header_length = 2;
  proto_item_set_len(th_item, header_length);
  proto_item_set_len(tlv_item, length);
    
  switch(type) {
  case BMX_DSC_TLV_CONTENT_HASH:
    tlv_c_item = proto_tree_add_item(tlv, hf_bmx7_tlv_chash, tvb, offset, -1, ENC_NA);
    proto_item_set_len(tlv_c_item, 28);
    offset+=28;
    bit_offset=offset*8;

    proto_tree_add_bits_item(tlv, hf_bmx7_tlv_chash_elength, tvb, bit_offset, 24, ENC_BIG_ENDIAN);
    offset+=3;
    proto_tree_add_item(tlv, hf_bmx7_tlv_type, tvb, offset, 1, ENC_NA);
    proto_tree_add_bits_item(tlv, hf_bmx7_tlv_chash_max_nesting, tvb, bit_offset+29, 2, ENC_BIG_ENDIAN);
    proto_tree_add_bits_item(tlv, hf_bmx7_tlv_chash_gzip, tvb, bit_offset+31, 1, ENC_BIG_ENDIAN);
    offset++;
    break;
  case BMX_DSC_TLV_VERSION:
    proto_tree_add_item(tlv, hf_bmx7_tlv_version_comp_version, tvb, offset, 1, ENC_NA);
    offset++;
    proto_tree_add_item(tlv, hf_bmx7_tlv_version_capabilities, tvb, offset, 1, ENC_NA);
    offset++;
    proto_tree_add_item(tlv, hf_bmx7_tlv_version_bootsqn, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;
    proto_tree_add_item(tlv, hf_bmx7_tlv_version_descsqn, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;
    proto_tree_add_item(tlv, hf_bmx7_tlv_version_ogm_sqn_range, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;
    tlv_v_item = proto_tree_add_item(tlv, hf_bmx7_tlv_version_ogm_chain_anchor, tvb, offset, -1, ENC_NA);
    proto_item_set_len(tlv_v_item, 28);
    offset+=28;
    bit_offset=offset*8;
    proto_tree_add_bits_item(tlv, hf_bmx7_tlv_version_content_length, tvb, bit_offset, 21, ENC_BIG_ENDIAN);
    proto_tree_add_bits_item(tlv, hf_bmx7_tlv_version_content, tvb, bit_offset+21, 11, ENC_BIG_ENDIAN);
    offset+=4;
    break;
  case BMX_DSC_TLV_DSC_SIGNATURE:
    proto_tree_add_item(tlv, hf_bmx7_tlv_dsc_signature_type, tvb, offset, 1, ENC_NA);
    offset++;
    tlv_s_item = proto_tree_add_item(tlv, hf_bmx7_tlv_dsc_signature, tvb, offset, -1, ENC_NA);
    proto_item_set_len(tlv_s_item, 256);
    offset+=32;
    break;
  case BMX_DSC_TLV_METRIC:
    proto_tree_add_item(tlv, hf_bmx7_tlv_metric_fmetric_min, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;
    proto_tree_add_item(tlv, hf_bmx7_tlv_metric_algo_type, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;
    proto_tree_add_item(tlv, hf_bmx7_tlv_metric_flags, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;
    bit_offset=offset*8;
    proto_tree_add_bits_item(tlv, hf_bmx7_tlv_metric_rp_exp_numerator, tvb, bit_offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_bits_item(tlv, hf_bmx7_tlv_metric_rp_exp_divisor, tvb, bit_offset+2, 2, ENC_BIG_ENDIAN);
    proto_tree_add_bits_item(tlv, hf_bmx7_tlv_metric_tp_exp_numerator, tvb, bit_offset+4, 2, ENC_BIG_ENDIAN);
    proto_tree_add_bits_item(tlv, hf_bmx7_tlv_metric_tp_exp_divisor, tvb, bit_offset+6, 2, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(tlv, hf_bmx7_tlv_metric_lq_tx_point_r255, tvb, offset, 1, ENC_NA);
    offset++;
    proto_tree_add_item(tlv, hf_bmx7_tlv_metric_lq_ty_point_r255, tvb, offset, 1, ENC_NA);
    offset++;
    proto_tree_add_item(tlv, hf_bmx7_tlv_metric_lq_t1_point_r255, tvb, offset, 1, ENC_NA);
    offset++;
    proto_tree_add_item(tlv, hf_bmx7_tlv_metric_ogm_link_rate_efficiency, tvb, offset, 1, ENC_NA);
    offset++;    
    proto_tree_add_item(tlv, hf_bmx7_tlv_metric_hops_history, tvb, offset, 1, ENC_NA);
    offset++;
    proto_tree_add_item(tlv, hf_bmx7_tlv_metric_hops_max, tvb, offset, 1, ENC_NA);
    offset++;
    proto_tree_add_item(tlv, hf_bmx7_tlv_metric_hops_penalty, tvb, offset, 1, ENC_NA);
    offset++;
    proto_tree_add_item(tlv, hf_bmx7_tlv_metric_ogm_sqn_best_hystere, tvb, offset, 1, ENC_NA);
    offset++;
    proto_tree_add_item(tlv, hf_bmx7_tlv_metric_ogm_sqn_late_hystere_100ms, tvb, offset, 1, ENC_NA);
    offset++;
    proto_tree_add_item(tlv, hf_bmx7_tlv_metric_ogm_metric_hystere_new_path, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;
    proto_tree_add_item(tlv, hf_bmx7_tlv_metric_ogm_metric_hystere_old_path, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;
    proto_tree_add_item(tlv, hf_bmx7_tlv_metric_ogm_interval_sec, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;
    bit_offset=offset*8;
    proto_tree_add_bits_item(tlv, hf_bmx7_tlv_metric_ogm_sqn_diff_max, tvb, bit_offset, 2, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(tlv, hf_bmx7_tlv_metric_ogm_link_throughput_efficiency, tvb, offset, 1, ENC_NA);
    offset+=3;
    break;
  case BMX_DSC_TLV_HNA6:
  case BMX_DSC_TLV_TUN6:
  case BMX_DSC_TLV_TUN4IN6_INGRESS:
  case BMX_DSC_TLV_TUN6IN6_INGRESS:
  case BMX_DSC_TLV_TUN4IN6_SRC:
  case BMX_DSC_TLV_TUN6IN6_SRC:
  case BMX_DSC_TLV_TUN4IN6_NET:
  case BMX_DSC_TLV_TUN6IN6_NET:
  case BMX_DSC_TLV_JSON_SMS:
  default:
    break;
  }
  return length;
}

static int
dissect_desc_adv(tvbuff_t *tvb, proto_item *ti, int offset, int length){
  gchar* pkid;
  guint8 reserved, reserved_ttl, *name;
  guint16 code_version,capabilities,dsc_sqn,min,range,tx_int,extension_len, 
    transmitter_iid;
  int i, processed, n;
  proto_tree *tree;
  proto_item *tlv_item;
    
  my_print("Calling desc adv!\n");
  tree = proto_item_add_subtree(ti, ett_bmx7_message);
  /* BMX7 don't have these fields *

     transmitter_iid = tvb_get_ntohs(tvb, offset);
     proto_tree_add_item(tree, hf_bmx7_transmitteriid4x, tvb, offset, 2, ENC_BIG_ENDIAN);
     offset +=2;
     name = tvb_get_string_enc(NULL, tvb, offset, DESCRIPTION0_ID_NAME_LEN, ENC_ASCII);
     proto_tree_add_item(tree, hf_bmx7_name, tvb, offset, DESCRIPTION0_ID_NAME_LEN, ENC_BIG_ENDIAN);
     offset += DESCRIPTION0_ID_NAME_LEN;
     pkid = tvb_bytes_to_str(NULL, tvb, offset, HASH_SHA1_LEN);
     proto_tree_add_item(tree, hf_bmx7_pkid, tvb, offset, HASH_SHA1_LEN, ENC_BIG_ENDIAN);
     offset+=HASH_SHA1_LEN;
     code_version = tvb_get_ntohs(tvb,offset);
     proto_tree_add_item(tree, hf_bmx7_code_version, tvb, offset, 2, ENC_BIG_ENDIAN);
     offset+=2;
     capabilities = tvb_get_ntohs(tvb, offset);
     proto_tree_add_item(tree, hf_bmx7_capabilities, tvb, offset, 2, ENC_BIG_ENDIAN);
     offset +=2;
     dsc_sqn = tvb_get_ntohs(tvb,offset);
     proto_tree_add_item(tree, hf_bmx7_description_sequence_number, tvb, offset, 2, ENC_BIG_ENDIAN);
     offset +=2;
     min = tvb_get_ntohs(tvb, offset);
     proto_tree_add_item(tree, hf_bmx7_originator_message_min_sqn, tvb, offset, 2, ENC_BIG_ENDIAN);
     offset +=2;
     range = tvb_get_ntohs(tvb, offset);
     proto_tree_add_item(tree, hf_bmx7_originator_message_range, tvb, offset, 2, ENC_BIG_ENDIAN);
     offset +=2;
     tx_int = tvb_get_ntohs(tvb, offset);
     proto_tree_add_item(tree, hf_bmx7_transmission_interval, tvb, offset, 2, ENC_BIG_ENDIAN);
     offset +=2;
     reserved_ttl = tvb_get_guint8(tvb, offset);
     proto_tree_add_item(tree, hf_bmx7_reserved_ttl, tvb, offset, 1, ENC_NA);
     offset++;
     reserved = tvb_get_guint8(tvb, offset);
     proto_tree_add_item(tree, hf_bmx7_reserved, tvb, offset, 1, ENC_NA);
     offset++;
     extension_len = tvb_get_ntohs(tvb, offset);
     proto_tree_add_item(tree, hf_bmx7_extension_length, tvb, offset, 2, ENC_BIG_ENDIAN);
     offset +=2;
     proto_item_set_len(ti, extension_len + MSG_DESC_ADV_SZ);
  */
  //Dissect TLVs:
  i=1;
  my_print("Offset is %d and length is %d\n", offset, length);
  while(offset < length ){
    tlv_item = proto_tree_add_item(tree, hf_bmx7_tlv, tvb, offset, -1, ENC_NA);
    proto_item_append_text(tlv_item, ": ");
    my_print("Calling TLV dissector!\n");
    n = dissect_bmx7_tlv(tvb, tlv_item, offset);
    offset += n;
    i++;
  }
  return offset;
}

static int
dissect_ogm_adv(tvbuff_t *tvb, proto_tree *tree, int offset, int end){
  AGGREG_SQN_T aggr_sqn;
  guint8 dest;
  OGM_MIX_T mix;
  OGM_SQN_T ogm_sqn;
  IID_T absolute, neigh;
  guint16 ogm_offset;
  int i;
  proto_tree *ogm;
  proto_item *ti;
    
  aggr_sqn = tvb_get_guint8(tvb, offset);
  proto_tree_add_item(tree, hf_bmx7_aggregation_sequence_number, tvb, offset, 1, ENC_NA);
  offset++;
  dest = tvb_get_guint8(tvb, offset);
  proto_tree_add_item(tree, hf_bmx7_ogm_destination_array, tvb, offset, 1, ENC_NA);
  offset++;
  //Skip the destination bytes
  offset += dest;
  i=1;
  neigh=0;
  while(offset<end){
    ti = proto_tree_add_item(tree, hf_bmx7_ogm, tvb, offset, 4, ENC_BIG_ENDIAN);
    ogm = proto_item_add_subtree(ti, ett_bmx7_message);
    mix = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(ogm, hf_bmx7_mix, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    ogm_offset = ((mix >> OGM_IIDOFFST_BIT_POS) & OGM_IIDOFFST_MASK);
    if(ogm_offset == OGM_IID_RSVD_JUMP){
      absolute = tvb_get_ntohs(tvb, offset);
      proto_tree_add_item(tree, hf_bmx7_iid, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;
      neigh = absolute;
    } else{
      ogm_sqn = tvb_get_ntohs(tvb, offset);
      proto_tree_add_item(tree, hf_bmx7_ogm_sequence_number, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset +=2;
      neigh += ogm_offset;
    }
    i++;
  }
  return offset;
}

//TODO add everywhere so that new trees are created
static int
dissect_ogm_ack(tvbuff_t *tvb, proto_tree *tree, int offset){
  OGM_DEST_T dest;
  AGGREG_SQN_T sqn;
    
  //OGM destination:
  dest = tvb_get_guint8(tvb, offset);
  proto_tree_add_item(tree, hf_bmx7_destination, tvb, offset, 1, ENC_NA);
  offset++;
    
  //Aggregation sqn being ack'ed:
  sqn = tvb_get_guint8(tvb, offset);
  proto_tree_add_item(tree, hf_bmx7_aggregation_sequence_number, tvb, offset, 1, ENC_NA);
  offset++;
    
  return offset;
}

static int
dissect_frame_header(tvbuff_t *tvb, proto_tree *frame_tree, unsigned int offset,
		     guint16 *length)
{
  proto_item *header_item;
  proto_tree *header_tree;
  guint8 type;
  unsigned int bit_offset, header_length;
    
  header_item = proto_tree_add_item(frame_tree, hf_bmx7_frame_header, tvb, offset, -1, ENC_NA);
  header_tree = proto_item_add_subtree(header_item, ett_bmx7_frame_header);
    
  //type
  bit_offset = offset*8;
  type = tvb_get_bits8(tvb, bit_offset, 1);
  proto_tree_add_item(header_tree, hf_bmx7_frame_type, tvb, 
		      offset, 1, ENC_NA);
  //length
  (*length) = tvb_get_ntohs(tvb, offset) & 0x7ff;
  proto_tree_add_bits_item(header_tree, hf_bmx7_frame_length16, tvb, 
			   bit_offset+5, 11, ENC_BIG_ENDIAN);
  offset+=2;
  header_length = 2;
    
  proto_item_set_len(header_item, header_length);
    
  return offset;
}

static int
dissect_bmx7_frame(tvbuff_t *tvb, proto_tree *bmx_tree, int version, 
		   unsigned int offset)
{
  guint8 type;
  guint16 length;
  unsigned int initial,i;
  proto_tree *frame_tree, *message_tree;
  proto_item *frame_item, *message_item;
    
  initial = offset;
  //Add the frame subtree:
  type = (tvb_get_guint8(tvb, offset) & 0xf8) >> 3;
  frame_item = proto_tree_add_item(bmx_tree, hf_bmx7_frame_type, tvb, offset, 1, ENC_NA);
  switch(type) {
  case FRAME_TYPE_HELLO_ADV:
    frame_tree = proto_item_add_subtree(frame_item, ett_bmx7_hello_adv);
    offset = dissect_frame_header(tvb, frame_tree, offset, &length);
    proto_item_set_len(frame_item, length);
    i = 1;
    while ( offset - initial < length) {
      message_item = proto_tree_add_item(frame_tree, hf_bmx7_hello, tvb, offset, 2, ENC_BIG_ENDIAN);
      i++;
      offset = dissect_hello_adv(tvb, message_item, offset, version);
    }
    break;
  case FRAME_TYPE_CONTENT_ADV:
    frame_tree = proto_item_add_subtree(frame_item, ett_bmx7_content_adv);
    offset = dissect_frame_header(tvb, frame_tree, offset, &length);
    proto_item_set_len(frame_item, length);
    //    offset = dissect_signature_adv(tvb, frame_tree, offset, initial+length);
    break;
  case FRAME_TYPE_CONTENT_REQ:
    frame_tree = proto_item_add_subtree(frame_item, ett_bmx7_content_req);
    offset = dissect_frame_header(tvb, frame_tree, offset, &length);
    proto_item_set_len(frame_item, length);
    //offset = dissect_signature_adv(tvb, frame_tree, offset, initial+length);
    break;
  case FRAME_TYPE_SIGNATURE_ADV:
    frame_tree = proto_item_add_subtree(frame_item, ett_bmx7_signature_adv);
    offset = dissect_frame_header(tvb, frame_tree, offset, &length);
    proto_item_set_len(frame_item, length);
    offset = dissect_signature_adv(tvb, frame_tree, offset, initial+length);
    break;
  case FRAME_TYPE_OGM_AGG_SQN_ADV:
    frame_tree = proto_item_add_subtree(frame_item, ett_bmx7_ogm_agg_sqn_adv);
    offset = dissect_frame_header(tvb, frame_tree, offset, &length);
    proto_item_set_len(frame_item, length);
    //Link advertisments are decoded at the same time all of them.
    offset = dissect_link_adv(tvb, frame_tree, offset, initial+length);
    break;
  case FRAME_TYPE_DEV_REQ:
    frame_tree = proto_item_add_subtree(frame_item, ett_bmx7_dev_req);
    offset = dissect_frame_header(tvb, frame_tree, offset, &length);
    proto_item_set_len(frame_item, length);
    while ( offset - initial < length) {
      offset = dissect_dev_req(tvb, frame_tree, offset);
    }
    break;
  case FRAME_TYPE_DEV_ADV:
    frame_tree = proto_item_add_subtree(frame_item, ett_bmx7_dev_adv);
    offset = dissect_frame_header(tvb, frame_tree, offset, &length);
    proto_item_set_len(frame_item, length);
    //Dev advertisments are decoded all at the same time:
    dissect_dev_adv(tvb, frame_tree, offset, initial+length);
    break;
  case FRAME_TYPE_HASH_REQ:
    frame_tree = proto_item_add_subtree(frame_item, ett_bmx7_hash_req);
    offset = dissect_frame_header(tvb, frame_tree, offset, &length);
    proto_item_set_len(frame_item, length);
    offset = dissect_hash_req(tvb, frame_tree, offset, initial+length);
    break;
  case FRAME_TYPE_HASH_ADV:
    frame_tree = proto_item_add_subtree(frame_item, ett_bmx7_hash_adv);
    offset = dissect_frame_header(tvb, frame_tree, offset, &length);
    proto_item_set_len(frame_item, length);
    i = 1;
    while ( offset - initial < length) {
      message_item = proto_tree_add_item(frame_tree, hf_bmx7_hash, tvb, offset, -1, ENC_BIG_ENDIAN);
      offset = dissect_hash_adv(tvb, message_item, offset);
      i++;
    }
    break;
  case FRAME_TYPE_DESC_REQ:
    frame_tree = proto_item_add_subtree(frame_item, ett_bmx7_desc_req);
    offset = dissect_frame_header(tvb, frame_tree, offset, &length);
    proto_item_set_len(frame_item, length);
    offset = dissect_hash_req(tvb, frame_tree, offset, initial+length);
    break;
  case FRAME_TYPE_DESC_ADV:
    frame_tree = proto_item_add_subtree(frame_item, ett_bmx7_desc_req);
    offset = dissect_frame_header(tvb, frame_tree, offset, &length);
    my_print("The length is %d\n", length);
    proto_item_set_len(frame_item, length);
    message_item = proto_tree_add_item(frame_tree, hf_bmx7_description, tvb, offset, -1, ENC_BIG_ENDIAN);
    offset = dissect_desc_adv(tvb, message_item, offset, initial+length);
    break;
  case FRAME_TYPE_OGM_ADV:
    frame_tree = proto_item_add_subtree(frame_item, ett_bmx7_ogm_adv);
    offset = dissect_frame_header(tvb, frame_tree, offset, &length);
    proto_item_set_len(frame_item, length);
    offset = dissect_ogm_adv(tvb, frame_tree, offset, length);
    break;
  case FRAME_TYPE_OGM_ACK:
    frame_tree = proto_item_add_subtree(frame_item, ett_bmx7_ogm_ack);
    offset = dissect_frame_header(tvb, frame_tree, offset, &length);
    proto_item_set_len(frame_item, length);
    while ( offset - initial < length) {
      offset = dissect_ogm_ack(tvb, frame_tree, offset);
    }
    break;
  default:
    //TODO new ett
    frame_tree = proto_item_add_subtree(frame_item, ett_bmx7_hello_adv);
    offset = dissect_frame_header(tvb, frame_tree, offset, &length);
    proto_item_set_len(frame_item, length);
    break;
  }
  return initial+length;
}
static int
dissect_bmx7(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  int offset = 0;
  int version,i;
  proto_item *bmx_item = NULL;
  proto_item *bmx_sub_item = NULL;
  proto_tree *bmx_tree = NULL;
  proto_tree *bmx_header_tree = NULL;
  gchar *hash;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_TAG_BMX);
  /* Clear out stuff in the info column */
  col_clear(pinfo->cinfo,COL_INFO);

  /* Dissect packet header */
  if (tree) { /* we are being asked for details */
    bmx_item = proto_tree_add_item(tree, proto_bmx7, tvb, 0, -1, ENC_NA);
    bmx_tree = proto_item_add_subtree(bmx_item, ett_bmx7);
    //version
    version = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(bmx_tree, hf_bmx7_version, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset +=2;
    //keyhash
    hash = tvb_bytes_to_str(NULL, tvb, offset, HASH_SHA224_LEN);
    proto_tree_add_string(bmx_tree, hf_bmx7_keyhash, tvb, offset, HASH_SHA224_LEN, hash);
    proto_item_set_len(bmx_item, 2 + HASH_SHA224_LEN);
    offset +=HASH_SHA224_LEN;
        
    /* Do frames */
    while(tvb_captured_length(tvb) - offset > 0){
      offset = dissect_bmx7_frame(tvb, bmx_tree, version, offset);
    }
  }

  return tvb_captured_length(tvb);
}

void
proto_register_bmx7(void)
{
  //BMX7 fields: (used for filters)
  static hf_register_info hf[] =
    {
#include "packet-bmx7-hf-array.c"
     { &hf_bmx7_version,
       { "version", "bmx7.version", FT_UINT8, BASE_DEC, NULL, 0x0,
	 "BMX7 VERSION", HFILL }},
     { &hf_bmx7_keyhash,
       { "keyhash", "bmx7.keyhash", FT_STRING, BASE_NONE, NULL, 0x0,
	 "Key hash", HFILL }},
     { &hf_bmx7_tx_iid,
       { "transmitter IID", "bmx7.tx_iid", FT_UINT16, BASE_DEC, NULL, 0x0,
	 "transmitter IID", HFILL }},
     { &hf_bmx7_link_sqn,
       { "link sqn", "bmx7.link_sqn", FT_UINT16, BASE_DEC, NULL, 0x0,
	 "Link advertisment sequence number", HFILL }},
     { &hf_bmx7_pkt_sqn,
       { "packet sqn", "bmx7.pkt_sqn", FT_UINT32, BASE_DEC, NULL, 0x0,
	 "Packet sequence number", HFILL }},
     { &hf_bmx7_local_id,
       { "Local ID", "bmx7.local_id", FT_UINT32, BASE_HEX, NULL, 0x0,
	 NULL, HFILL }},
     { &hf_bmx7_dev_idx,
       { "Device idx", "bmx7.dev_idx", FT_UINT8, BASE_DEC, NULL, 0x0,
	 NULL, HFILL }},
     { &hf_bmx7_frame_is_short,
       { "Short frame", "bmx7.frame.short", FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x0,
	 "Lenth of the frame format", HFILL }},
     { &hf_bmx7_frame_is_relevant,
       { "Relevant frame", "bmx7.frame.relevant", FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x0,
	 "Relevancy of the frame", HFILL }},
     { &hf_bmx7_frame_type,
       { "Frame type", "bmx7.frame.type", FT_UINT8, BASE_DEC, VALS(bmx_frame_types), FRAME_TYPE_MASK,
	 "Frame type", HFILL}}, 
     { &hf_bmx7_tlv_type,
       { "TLV type", "bmx7.tlv.type", FT_UINT8, BASE_DEC, VALS(bmx_tlv_types), TLV_TYPE_MASK,
	 "TLV type", HFILL}}, 
     { &hf_bmx7_frame_length8,
       { "Frame length", "bmx7.frame.length", FT_UINT8, BASE_DEC, NULL, 0x00,
	 "Length of the frame" , HFILL}},
     { &hf_bmx7_frame_length16,
       { "Frame length (11 bit)", "bmx7.frame.length", FT_UINT16, BASE_DEC, NULL, 0x00,
	 "Length of the frame", HFILL}},
     { &hf_bmx7_hello_sqn,
       { "Hello sqn", "bmx7.hello.sqn", FT_UINT16, BASE_DEC,NULL, 0x0,
	 "Hello sequence number", HFILL}},
    };

  //BMX7 trees (how they expand down the data)
  static gint *ett[] =
    {
     &ett_bmx7,
     &ett_bmx7_version,
     &ett_bmx7_keyhash,
     &ett_bmx7_tx_iid,
     &ett_bmx7_link_sqn,
     &ett_bmx7_pkt_sqn,
     &ett_bmx7_local_id,
     &ett_bmx7_dev_idx,
     &ett_bmx7_frame_header,
     &ett_bmx7_hello_adv,
     &ett_bmx7_rp_adv,
     &ett_bmx7_content_adv,
     &ett_bmx7_content_req,
     &ett_bmx7_signature_adv,
     &ett_bmx7_ogm_agg_sqn_adv,
     &ett_bmx7_link,
     &ett_bmx7_dev_req,
     &ett_bmx7_dev_adv,
     &ett_bmx7_hash_req,
     &ett_bmx7_hash_adv,
     &ett_bmx7_desc_req,
     &ett_bmx7_desc_adv,
     &ett_bmx7_ogm_adv,
     &ett_bmx7_ogm_ack,
     &ett_bmx7_tlv_header,
     &ett_bmx7_tlv_content_hash,
     &ett_bmx7_tlv_dsc_signature,
     &ett_bmx7_tlv_version,
     &ett_bmx7_tlv_rsa_link_pubkey,
     &ett_bmx7_tlv_dhm_link_pubkey,
     &ett_bmx7_tlv_metric,
     &ett_bmx7_tlv_llip,
     &ett_bmx7_tlv_uhna4,
     &ett_bmx7_tlv_hna6,
     &ett_bmx7_tlv_tun6,
     &ett_bmx7_tlv_tun4in6_ingress,
     &ett_bmx7_tlv_tun6in6_ingress,
     &ett_bmx7_tlv_tun4in6_src,
     &ett_bmx7_tlv_tun6in6_src,
     &ett_bmx7_tlv_tun4in6_net,
     &ett_bmx7_tlv_tun6in6_net,
     &ett_bmx7_tlv_info,
     &ett_bmx7_tlv_json_sms,
     &ett_bmx7_message,
    };

  //Protocol, field and trees registrations
  proto_bmx7 = proto_register_protocol("BMX7", "BMX7", "bmx7");
  proto_register_field_array(proto_bmx7, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));


}

void
proto_reg_handoff_bmx7(void)
{
  dissector_handle_t bmx7_handle;

  bmx7_handle = create_dissector_handle(dissect_bmx7, proto_bmx7);
  dissector_add_uint("udp.port", 6270, bmx7_handle);
}
