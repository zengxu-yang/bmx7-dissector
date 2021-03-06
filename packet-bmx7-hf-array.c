/* Generated from convert_proto_tree_add_text.pl */
      { &hf_bmx7_destination_local_id, { "Destination local id", "bmx7.destination_local_id", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_bmx7_device_sequence_number, { "Device sequence number", "bmx7.device_sequence_number", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_bmx7_link, { "Link", "bmx7.link", FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_bmx7_transmitter_device_id, { "Transmitter device id", "bmx7.transmitter_device_id", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_bmx7_peer_device_id, { "Peer device id", "bmx7.peer_device_id", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_bmx7_peer_local_id, { "Peer local id", "bmx7.peer_local_id", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_bmx7_device, { "Device", "bmx7.device", FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_bmx7_device_index, { "Device index", "bmx7.device_index", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_bmx7_channel, { "Channel", "bmx7.channel", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_bmx7_transmitter_min_bitrate, { "Transmitter min bitrate", "bmx7.transmitter_min_bitrate", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_bmx7_transmitter_max_bitrate, { "Transmitter max bitrate", "bmx7.transmitter_max_bitrate", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_bmx7_local_ipv6, { "Local IPv6", "bmx7.local_ipv6", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_bmx7_mac_address, { "Mac address", "bmx7.mac_address", FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_bmx7_request, { "Request", "bmx7.request", FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_bmx7_transmitteriid4x, { "Transmitter IID4x", "bmx7.transmitteriid4x", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_bmx7_iid_req_dest_nodeid, { "Destination NodeID", "bmx7.iid_req_dest_nodeid", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
	{ &hf_bmx7_receiveriid4x, { "Receiver IID4x", "bmx7.receiveriid4x", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_bmx7_desc_sqn, { "Desc SQN", "bmx7.desc_sqn", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_bmx7_burst_sqn, { "Burst SQN", "bmx7.burst_sqn", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_bmx7_signature_type, { "Signature Type", "bmx7.signature_type", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_bmx7_signature, { "Signature", "bmx7.signature", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_bmx7_description_hash, { "Description hash", "bmx7.description_hash", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_bmx7_tlv_header, { "TLV header", "bmx7.tlv_header", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_bmx7_tlv_version_comp_version, { "Compatibility Version", "bmx7.tlv_version_comp_version", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_bmx7_tlv_version_capabilities, { "Capabilities", "bmx7.tlv_version_capabilities", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_bmx7_tlv_version_bootsqn, { "Boot SQN", "bmx7.tlv_version_bootsqn", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_bmx7_descsqn, { "Desc SQN", "bmx7.descsqn", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_bmx7_tlv_version_ogm_sqn_range, { "OGM SQN Range", "bmx7.tlv_version_ogm_sqn_range", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_bmx7_tlv_version_ogm_chain_anchor, { "OGM Chain Anchor", "bmx7.tlv_version_ogm_chain_anchor", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_bmx7_tlv_version_content_length, { "Content Length", "bmx7.tlv_version_ogm_chain_anchor", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_bmx7_tlv_version_content, { "Content", "bmx7.tlv_version_content", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_bmx7_tlv_dsc_signature_type, { "Type", "bmx7.tlv_dsc_signature_type", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_bmx7_tlv_dsc_signature, { "Signature (2048 bits)", "bmx7.tlv_dsc_signature", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_bmx7_tlv_chash, { "Hash", "bmx7.tlv_chash", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_bmx7_tlv_chash_etype, { "Expanded Type", "bmx7.tlv_chash_etype", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_bmx7_tlv_chash_max_nesting, { "Max Nesting", "bmx7.tlv_chash_max_nesting", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_bmx7_tlv_chash_gzip, { "GZip", "bmx7.tlv_chash_gzip", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_bmx7_tlv_chash_elength, { "Expanded Length", "bmx7.tlv_chash_elength", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_bmx7_tlv_metric_fmetric_min, { "FMetric Min", "bmx7.tlv_metric_fmetric_min", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_bmx7_tlv_metric_algo_type, { "Algorithm Type", "bmx7.tlv_metric_algo_type", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_bmx7_tlv_metric_flags, { "Flags", "bmx7.tlv_metric_flags", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
	{ &hf_bmx7_tlv_metric_rp_exp_numerator, { "RP Exponent Numerator", "bmx7.tlv_metric_rp_exp_numerator", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_bmx7_tlv_metric_rp_exp_divisor, { "RP Exponent Divisor", "bmx7.tlv_metric_rp_exp_divisor", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_bmx7_tlv_metric_tp_exp_numerator, { "TP Exponent Numerator", "bmx7.tlv_metric_tp_exp_numerator", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_bmx7_tlv_metric_tp_exp_divisor, { "TP Exponent Divisor", "bmx7.tlv_metric_tp_exp_divisor", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_bmx7_tlv_metric_lq_tx_point_r255, { "LQ TX Point R255", "bmx7.tlv_metric_lq_tx_point_r255", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_bmx7_tlv_metric_lq_ty_point_r255, { "LQ TY Point R255", "bmx7.tlv_metric_lq_ty_point_r255", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_bmx7_tlv_metric_lq_t1_point_r255, { "LQ T1 Point R255", "bmx7.tlv_metric_lq_t1_point_r255", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_bmx7_tlv_metric_ogm_link_rate_efficiency, { "OGM Link Rate Efficiency", "bmx7.tlv_metric_ogm_link_rate_efficiency", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_bmx7_tlv_metric_hops_history, { "Hops History", "bmx7.tlv_metric_hops_history", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_bmx7_tlv_metric_hops_max, { "Hops Max", "bmx7.tlv_metric_hops_max", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_bmx7_tlv_metric_hops_penalty, { "Hops Penalty", "bmx7.tlv_metric_hops_penalty", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_bmx7_tlv_metric_ogm_sqn_best_hystere, { "OGM SQN Best Hystere", "bmx7.tlv_metric_ogm_sqn_best_hystere", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_bmx7_tlv_metric_ogm_sqn_late_hystere_100ms, { "OGM SQN Late Hystere 100ms", "bmx7.tlv_metric_ogm_sqn_late_hystere_100ms", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_bmx7_tlv_metric_ogm_metric_hystere_new_path, { "OGM Metric Hystere New Path", "bmx7.tlv_metric_ogm_metric_hystere_new_path", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_bmx7_tlv_metric_ogm_metric_hystere_old_path, { "OGM Metric Hystere Old Path", "bmx7.tlv_metric_ogm_metric_hystere_old_path", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_bmx7_tlv_metric_ogm_interval_sec, { "OGM Interval (Sec)", "bmx7.tlv_metric_ogm_interval_sec", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_bmx7_tlv_metric_ogm_sqn_diff_max, { "OGM SQN Max Difference", "bmx7.tlv_metric_ogm_sqn_diff_max", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_bmx7_tlv_metric_ogm_link_throughput_efficiency, { "OGM Link Throughput Efficiency", "bmx7.tlv_metric_ogm_link_throughput_efficiency", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_bmx7_ogm_agg_sqn_max, { "OGM Aggregation Max SQN", "bmx7.ogm_agg_sqn_max", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_bmx7_ogm_agg_sqn_size, { "OGM Aggregation SQN Size", "bmx7.ogm_agg_sqn_size", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_bmx7_ogm_adv_metric, { "OGM Aggregation Metric", "bmx7.ogm_adv_metric", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
	{ &hf_bmx7_ogm_adv_more, { "More", "bmx7.ogm_adv_more", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_bmx7_ogm_adv_transmitteriid4x, { "Transmitter IID4X", "bmx7.ogm_adv_transmitteriid4x", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_bmx7_ogm_adv_hopcount, { "Hop Count", "bmx7.ogm_adv_hopcount", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_bmx7_ogm_adv_metric_exp, { "Metric Exponent", "bmx7.ogm_adv_metric_exp", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_bmx7_ogm_adv_metric_mantissa, { "Metric Mantissa", "bmx7.ogm_adv_metric_mantissa", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_bmx7_ogm_adv_metric_t0, { "Metric", "bmx7.ogm_adv_metric_t0", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_bmx7_ogm_adv_more_t0, { "More", "bmx7.ogm_adv_more_t0", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_bmx7_ogm_adv_type_t0, { "Type", "bmx7.ogm_adv_type_t0", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_bmx7_ogm_adv_directional_t0, { "Directional", "bmx7.ogm_adv_directional_t0", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_bmx7_ogm_adv_metric_exp_t0, { "Metric Exponent", "bmx7.ogm_adv_metric_exp_t0", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_bmx7_ogm_adv_metric_mantissa_t0, { "Metric Mantissa", "bmx7.ogm_adv_metric_mantissa_t0", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_bmx7_ogm_adv_channel_t0, { "Channel", "bmx7.ogm_adv_channel_t0", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_bmx7_hello_reply_dhash_dest_dhash, { "Destination Hash", "bmx7.hello_reply_dhash_dest_hash", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
	{ &hf_bmx7_hello_reply_dhash_rxlq, { "RX LQ", "bmx7.hello_reply_dhash_dest_hash", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_bmx7_hello_reply_dhash_receiverdevidx, { "Receiver Device Idx", "bmx7.hello_reply_dhash_receiverDevIdx", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_bmx7_content_dest_khash, { "Content Destination Keyhash", "bmx7.content_dest_khash", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
	{ &hf_bmx7_iid_adv_nodeid, { "Node ID", "bmx7.iid_adv_nodeid", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
	{ &hf_bmx7_content_dest_chash, { "Content Destination Content-hash", "bmx7.content_dest_chash", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
	{ &hf_bmx7_content_adv_hdr, { "Content ADV Header", "bmx7.content_adv_hdr", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_bmx7_content_adv_max_nesting, { "Max Nesting", "bmx7.content_adv_max_nesting", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_bmx7_content_adv_gzip, { "GZip", "bmx7.content_av_gzip", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	{ &hf_bmx7_content_adv_content, { "Advertised Content", "bmx7.content_adv_content", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
	{ &hf_bmx7_desc_dest_khash, { "Description Destination Keyhash", "bmx7.desc_dest_khash", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
	{ &hf_bmx7_desc_khash, { "Description Keyhash", "bmx7.desc_khash", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_bmx7_reserved_bytes, { "Reserved bytes", "bmx7.reserved_bytes", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_bmx7_name, { "Name", "bmx7.name", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_bmx7_pkid, { "pkid", "bmx7.pkid", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_bmx7_code_version, { "Code version", "bmx7.code_version", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_bmx7_capabilities, { "Capabilities", "bmx7.capabilities", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_bmx7_description_sequence_number, { "Description sequence number", "bmx7.description_sequence_number", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_bmx7_originator_message_min_sqn, { "Originator message min sqn", "bmx7.originator_message_min_sqn", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_bmx7_originator_message_range, { "Originator message range", "bmx7.originator_message_range", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_bmx7_transmission_interval, { "Transmission interval", "bmx7.transmission_interval", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_bmx7_reserved_ttl, { "Reserved TTL", "bmx7.reserved_ttl", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_bmx7_reserved, { "Reserved", "bmx7.reserved", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_bmx7_extension_length, { "Extension Length", "bmx7.extension_length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_bmx7_tlv, { "TLV", "bmx7.tlv", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_bmx7_random_part_of_the_name, { "Random part of the name", "bmx7.random_part_of_the_name", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_bmx7_description_tlvs_length, { "Description TLVs length", "bmx7.description_tlvs_length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_bmx7_max_ttl, { "Max TTL", "bmx7.max_ttl", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_bmx7_aggregation_sequence_number, { "Aggregation sequence number", "bmx7.aggregation_sequence_number", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_bmx7_chainogm, { "Chain Ogm", "bmx7.chainogm", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_bmx7_mix, { "Mix", "bmx7.mix", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_bmx7_iid, { "IID", "bmx7.iid", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_bmx7_ogm_sequence_number, { "%u. OGM sequence number", "bmx7_ogm_sequence_number", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_bmx7_destination, { "Destination NodeID", "bmx7.destination", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_bmx7_frame_header, { "Frame header", "bmx7.frame_header", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_bmx7_hello, { "Hello", "bmx7.hello", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_bmx7_hash, { "Hash", "bmx7.hash", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_bmx7_description, { "Description", "bmx7.description", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},


      /* Generated from convert_proto_tree_add_text.pl */
