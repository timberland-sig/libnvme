/*
 * nbft.c
 *
 * Copyright (c) 2021-2022, Dell Inc. or its subsidiaries.  All Rights Reserved.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include <arpa/inet.h>

#include "private.h"
#include "nbft.h"
#include "log.h"

/*
 *  ACPI NBFT table structures (spec v0.36)
 */
#define NBFT_ACPI_SIG		"NBFT"

enum nbft_raw_sub_structure_type {
	NBFT_HEADER,
	NBFT_CONTROL,
	NBFT_HOST,
	NBFT_HFI_HEADER,
	NBFT_HFI_TRANSPORT,
	NBFT_HFI_EXTENDED_ADAPTER_INFO,
	NBFT_SNSS,
	NBFT_SNSS_EXTENDED_INFO,
	NBFT_SECURITY,
	NBFT_DISCOVERY,
	NBFT_HFI_INFO,
};

/*
 * HEADER (Table 3)
 */
struct __attribute__((__packed__)) raw_nbft_header {
	char signature[4];	/* ASCII table signature */
	__u32 length;		/* Length of table in bytes, including this header */
	__u8 revision;		/* ACPI Specification minor version number */
	__u8 checksum;		/* To make sum of entire table == 0 */
	char oem_id[6];		/* ASCII OEM identification */
	char oem_table_id[8];	/* ASCII OEM table identification */
	__u32 oem_revision;	/* OEM revision number */
	__u32 creator_id;
	__u32 creator_revision;
	__u16 heap_offset;
	__u16 heap_length;
	__u16 driver_dev_path_sig_offset;
	__u16 driver_dev_path_sig_length;
	__u8 reserved[4];
};

/*
 * CONTROL (Table 4)
 */
struct __attribute__((__packed__)) raw_nbft_control {
	__u8 structure_id;
	__u8 version;
	__u16 length;
	__u8 flags;
	__u8 num_hfi;
	__u16 number_of_namespaces;
	__u8 num_security_profiles;
	__u8 num_discovery_entries;
	__u16 host_structure_offset;
	__u16 hfi_1_offset;
	__u16 namespace_1_offset;
	__u16 security_profile_1_offset;
	__u16 discovery_structure_1_offset;
	__u8 reserved2[12];
};

enum control_flags {
	CONTROLFLAG_BLOCK_VALID,
	CONTROLFLAG_BOOT_FAILOVER_MULTIPATH_FEATURE,
};

/*
 * HOST (Table 6)
 */
struct __attribute__((__packed__)) raw_nbft_host {
	__u8 structure_id;
	__u8 version;
	__u16 length;
	__u8 host_flags;
	uuid_t host_identifier;
	__u16 host_nqn_offset;
	__u16 host_nqn_length;
	__u8 reserved[7];
};

enum host_flags {
	HOSTFLAG_BLOCK_VALID,
};

/*
 * HFI (Table 8)
 */
struct __attribute__((__packed__)) raw_nbft_hfi {
	__u8 structure_id;
	__u8 version;
	__u8 length;
	__u8 index;
	__u8 hfi_flags;
	__u8 hfi_transport_type;
	__u16 hostid_offset;
	__u16 hostid_length;
	__u16 hostnqn_offset;
	__u16 hostnqn_length;
	__u16 info_structure_offset;
	__u16 info_structure_length;
};

enum hfi_flags {
	HFIFLAG_BLOCK_VALID,
	HFIFLAG_DEVICE_ADVANCED_CAPABILITIES,
	HFIFLAG_HOSTID_OVERRIDE,
	HFIFLAG_HOSTNQN_OVERRIDE,
};

/*
 * HFI INFO (Table 10)
 */
struct __attribute__((__packed__)) raw_nbft_hfi_info_tcp {
	__u8 structure_id;
	__u8 version;
	__u8 length;
	__u8 hfi_transport_type;
	__u16 hfi_index;
	__u8 transport_flags;
	__u32 pci_sbdf;
	__u8 mac_addr[6];
	__u16 vlan; // 4096 if unset
	__u8 origin;
	__u8 ip_address[16];
	__u8 subnet_mask_prefix;
	__u8 ip_gateway[16];
	__u16 route_metric;
	__u8 primary_dns[16];
	__u8 secondary_dns[16];
	__u8 dhcp_server[16];
	__u16 host_name_offset;
	__u16 host_name_length;
	__u16 extended_adapter_info_offset;
	__u16 extended_adapter_info_length;
};

enum hfi_info_tcp_flags {
	HFIINFOTCPFLAG_BLOCK_VALID,
	HFIINFOTCPFLAG_GLOBAL_ROUTE_VS_LINK_LOCAL_OVERRIDE,
	HFIINFOTCPFLAG_DHCP_OVERRIDE,
	HFIINFOTCPFLAG_OEM_EXTENDED_ADAPTER_INFO,
};

struct __attribute__((__packed__)) raw_nbft_hfi_info_tcp_extended_info {
	__u8 structure_id;
	__u8 version;
	__u8 length;
	__u16 hfi_index;
	__u8 extended_capabilities;
};

enum hfi_info_tcp_extended_info_extended_capabilities {
	HFIINFOTCPEXTENDEDCAP_TRANSPORT_OFFLOAD,
};

/*
 * HFI Info Extended Adapter Information (Table 12)
 */
struct __attribute__((__packed__)) raw_nbft_hfi_info_extended_adapter_info {
	__u8 structure_id;
	__u8 version;
	__u8 length;
	__u16 hfi_index;
	__u8 extended_capabilities;
};

enum hfi_info_extended_adapter_info_flags {
	HFIINFOEXTADAPTERINFOFLAG_TRANSPORT_OFFLOAD,
};

/*
 * SUBSYSTEM NAMESPACE (Table 14)
 */
struct __attribute__((__packed__)) raw_nbft_snss {
	__u8 structure_id;
	__u8 version;
	__u16 length;
	__u16 index;
	__u16 subsystem_namespace_flags;
	__u8 transport_type;
	__u8 primary_discovery_ctrl_offset;
	__u8 subsystem_transport_address[16];
	__u16 subsystem_transport_svcid; // default is 4420
	__u16 subsystem_port_id;
	__u32 nsid;
	__u8 nid_type;
	__u8 nid[16];
	__u8 security_struct_index;  // 0 for none
	__u16 hfi_association_offset;
	__u16 hfi_association_length;
	__u16 subsystem_namespace_nqn_offset;
	__u16 subsystem_namespace_nqn_length;
	__u16 snss_extended_info_offset; // valid if flags bit4 is set
	__u16 snss_extended_info_length;
};

enum snss_flags {
	NSFLAG_BLOCK_VALID,
	NSFLAG_NON_BOOTABLE_ENTRY,
	NSFLAG_USE_SECURITY_FIELD,
	NSFLAG_DHCP_ROOT_PATH_OVERRIDE,
	NSFLAG_SNSS_EXTENDED_INFO_IN_USE,
	NSFLAG_SEPARATE_DISCOVERY_CONTROLLER,
	NSFLAG_PDU_HEADER_DIGEST,
	NSFLAG_DATA_DIGEST,
	NSFLAG_DISCOVERED_NAMESPACE,
	NSFLAG_UNAVAILABLE_NAMESPACE,
};

/*
 * SNSS: Subsystem Namespace Structure Extended Information Sub-Structure (Table 16)
 */
struct __attribute__((__packed__)) raw_nbft_snss_extended_info {
	__u8 structure_id;
	__u8 version;
	__u8 length;
	__u16 snss_index;
	__u32 flags;
	__u16 controller_id; // optional
	__u8 mp_group;
	__u16 asqsz; //Admin submission queue size
};

enum snss_extended_info_flags {
	SNSSFLAG_BLOCK_VALID,
	SNSSFLAG_MULTIPATH_VOLUME_MEMBER_ENABLED,
};

/*
 * SECURITY (Table 18)
 */
struct __attribute__((__packed__)) raw_nbft_security {
	__u8 structure_id;
	__u8 version;
	__u16 length;
	__u8 index;
	__u16 security_structure_flags;
	__u8 secret_type;
	__u16 secure_channel_allowed_algorithms_offset;
	__u16 secure_channel_allowed_algorithms_length;
	__u16 authentication_protocols_allowed_offset;
	__u16 authentication_protocols_allowed_length;
	__u16 cipher_suite_name_offset;
	__u16 cipher_suite_name_length;
	__u16 supported_dh_groups_offset;
	__u16 supported_dh_groups_length;
	__u16 secure_hash_functions_offset;
	__u16 secure_hash_functions_length;
	__u16 secret_keypath_offset;
	__u16 secret_keypath_length;
	__u16 extended_authentication_offset;
	__u16 extended_authentication_length;
};

enum security_profile_flags {
	/* 0 */ SECFLAG_BLOCK_VALID,
	/* 1 */ SECFLAG_IN_BAND_AUTHENTICATION_REQUIRED,
	/* 2 */ SECFLAG_AUTHENTICATION_POLICY_LIST,
	/* 3 */ SECFLAG_SECURE_CHANNEL_NEGOTIATION_REQUIRED,
	/* 4 */ SECFLAG_SECURITY_POLICY_LIST,
	/* 5 */ SECFLAG_CIPHER_SUITES_RESTRICTED_BY_POLICY,
	/* 6 */ SECFLAG_AUTHENTICATION_PARAMETERS_RESTRICTED_BY_POLICY,
	/* 7 */ SECFLAG_EXTENDED_AUTHENTICATION_PARAMETERS_PRESENT,
	/* 8 */ SECFLAG_AUTHENTICATION_VERIFICATION_ENTITY_REQUIRED,
	/* 9 */ SECFLAG_AUTHENTICATION_DH_GROUPS_RESTRICTED_BY_POLICY_LIST,
	/* 10 */ SECFLAG_SECURE_HASH_FUNCTIONS_POLICY_LIST,
};

enum secret_type {
	SECRET_TYPE_NONE,
	SECRET_TYPE_REDFISH_HOST_INTERFACE_URI,
	SECRET_TYPE_OEM_URI,
};

/*
 * DISCOVERY (Table 21)
 */
struct __attribute__((__packed__)) raw_nbft_discovery {
	__u8 structure_id;
	__u8 version;
	__u16 length;
	__u8 discovery_structure_flags;
	__u8 index;
	__u8 discovery_record_hfi;
	__u8 discovery_record_security_profile;
	__u16 discovery_ctrl_addr_offset;
	__u16 discovery_ctrl_addr_length;
	__u16 discovery_controller_nqn_offset;
	__u16 discovery_controller_nqn_length;
};

enum discovery_flags {
	DISCOVERYFLAGS_BLOCK_VALID,
};
/*
 *  End of NBFT ACPI table definitions
 */

static __u8 csum(void *buffer, int length)
{
	int n;
	__u8 sum = 0;

	for (n = 0; n < length; n++) {
		sum = (__u8)(sum + ((__u8 *)buffer)[n]);
	}
	return sum;
}

static void format_ip_addr(char *buf, size_t buflen, __u8 *addr) {
	struct in6_addr *addr_ipv6;

	addr_ipv6 = (struct in6_addr *)addr;
	if (   addr_ipv6->s6_addr32[0] == 0
	    && addr_ipv6->s6_addr32[1] == 0
	    && (ntohl(addr_ipv6->s6_addr32[2]) == 0xffff) )
		/* ipv4 */
		inet_ntop(AF_INET, &(addr_ipv6->s6_addr32[3]), buf, buflen);
	else
		/* ipv6 */
		inet_ntop(AF_INET6, addr_ipv6, buf, buflen);
}

static int in_heap(struct raw_nbft_header *header, __u16 length, __u16 offset)
{
	if (length == 0)
		return 1;
	if (offset < header->heap_offset)
		goto bad;
	if (offset > header->heap_offset + header->heap_length)
		goto bad;
	if (offset + length > header->heap_offset + header->heap_length)
		goto bad;
	return 1;
bad:
	return 0;
}

/*
 *  Return transport_type string (NBFT Table 2)
 */
static char *trtype_to_string(__u8 transport_type)
{
	switch (transport_type) {
		case 1:
			return "tcp";
			break;
		default:
			return "invalid";
			break;
	}
}

#define verify(condition, message)							\
	if (!(condition)) {								\
		nvme_msg(NULL, LOG_DEBUG, "file %s: " message "\n", nbft->filename);	\
		return -EINVAL;								\
	}

static int __get_and_verify_heap_ptr(struct raw_nbft_header *header,
				       const char *filename, const char *subtablename, const char *fieldname,
				       __u16 length, __u16 offset, bool is_string,
				       char **output)
{
	if (length == 0) {
		*output = NULL;
		return 0;
	}

	if (!in_heap(header, length, offset)) {
		nvme_msg(NULL, LOG_DEBUG, "file %s: field '%s' in subtable '%s' has invalid offset or length\n",
			 filename, fieldname, subtablename);
		return -EINVAL;
	}

	/* check that string is zero terminated correctly */
	*output = (char *)header + offset;

	if (is_string) {
		if (strnlen(*output, length + 1) < length)
			nvme_msg(NULL, LOG_DEBUG, "file %s: string '%s' in subtable '%s' is shorter (%ld) than specified length (%d)\n",
				filename, fieldname, subtablename, strnlen(*output, length+1), length);
		else if (strnlen(*output, length + 1) > length) {
			nvme_msg(NULL, LOG_DEBUG, "file %s: string '%s' in subtable '%s' is not zero terminated\n",
				 filename, fieldname, subtablename);
			return -EINVAL;
		}
	}

	return 0;
}

#define get_and_verify_heap_ptr(subtable, fieldname, is_string,output)						\
	__get_and_verify_heap_ptr(header,									\
				    nbft->filename, stringify(subtable), stringify(fieldname),			\
				    subtable ->fieldname##_length, subtable ->fieldname##_offset, is_string,	\
				    output)

static struct nbft_discovery *discovery_index(struct nbft_info *nbft, int i)
{
	struct nbft_discovery *d;

	list_for_each(&nbft->discovery_list, d, node)
		if (d->index == i)
			return d;
	return NULL;
}

static struct nbft_hfi *hfi_index(struct nbft_info *nbft, int i)
{
	struct nbft_hfi *h;

	list_for_each(&nbft->hfi_list, h, node)
		if (h->index == i)
			return h;
	return NULL;
}

static struct nbft_security *security_index(struct nbft_info *nbft, int i)
{
	struct nbft_security *s;

	list_for_each(&nbft->security_list, s, node)
		if (s->index == i)
			return s;
	return NULL;
}

static int read_snss(struct nbft_info *nbft, struct raw_nbft_snss *raw_snss, struct nbft_subsystem_ns **s)
{
	struct raw_nbft_header *header;
	struct nbft_subsystem_ns *ss;
	__u8 *ss_hfi_indexes;
	int i, ret;

	if (!(raw_snss->subsystem_namespace_flags & (1 << NSFLAG_BLOCK_VALID)))
		return -EINVAL;
	ss = calloc(1, sizeof(*ss));
	if (!ss) {
		return -ENOMEM;
	}

	header = (struct raw_nbft_header *)nbft->raw_nbft;

	ss->index = raw_snss->index;
	strncpy(ss->transport, trtype_to_string(raw_snss->transport_type), sizeof(ss->transport));
	format_ip_addr(ss->transport_address, sizeof(ss->transport_address), raw_snss->subsystem_transport_address);
	snprintf(ss->transport_svcid, sizeof(ss->transport_svcid), "%d", raw_snss->subsystem_transport_svcid);
	ss->subsys_port_id = raw_snss->subsystem_port_id;
	ss->nsid = raw_snss->nsid;
	ss->nid_type = raw_snss->nid_type;
	ss->nid = raw_snss->nid;
	if (get_and_verify_heap_ptr(raw_snss, subsystem_namespace_nqn, 1, &ss->subsys_nqn)) {
		ret = -EINVAL;
		goto fail;
	}

	/*
	 * discovery controller offset is actually discovery controller index
	 * nbft v0.36 is broken
	 */
	if (raw_snss->primary_discovery_ctrl_offset) {
		ss->discovery = discovery_index(nbft, raw_snss->primary_discovery_ctrl_offset);
		if (!ss->discovery)
			nvme_msg(NULL, LOG_DEBUG, "file %s: namespace %d discovery controller not found\n",
				 nbft->filename, ss->index);
	}

	if (get_and_verify_heap_ptr(raw_snss, hfi_association, 0, (char **)&ss_hfi_indexes)) {
		ret = -EINVAL;
		goto fail;
	}

	ss->hfis = calloc(raw_snss->hfi_association_length, sizeof(*ss->hfis));
	if (!ss->hfis) {
		ret = -ENOMEM;
		goto fail;
	}

	for (i = 0; i < raw_snss->hfi_association_length; i++) {
		ss->hfis[i] = hfi_index(nbft, ss_hfi_indexes[i]);
		if (ss_hfi_indexes[i] && !ss->hfis[i])
			nvme_msg(NULL, LOG_DEBUG, "file %s: namespace %d HFI %d not found\n",
				nbft->filename, ss->index, ss_hfi_indexes[i]);
		else
			ss->num_hfis++;
	}

	*s = ss;
	return 0;

fail:
	free(ss);
	return ret;
}

static int read_hfi_info_tcp(struct nbft_info *nbft, struct raw_nbft_hfi_info_tcp *raw_hfi_info_tcp, struct nbft_hfi *hfi)
{
	struct raw_nbft_header *header;

	header = (struct raw_nbft_header *)nbft->raw_nbft;

	// could verify structure ID, version, length, and transport type here
	if ((raw_hfi_info_tcp->transport_flags & (1 << HFIINFOTCPFLAG_BLOCK_VALID)) == 0) {
		return -EINVAL;
	}

	hfi->tcp_info.pci_sbdf = raw_hfi_info_tcp->pci_sbdf;
	hfi->tcp_info.mac_addr = raw_hfi_info_tcp->mac_addr;
	hfi->tcp_info.vlan = raw_hfi_info_tcp->vlan;
	hfi->tcp_info.origin = raw_hfi_info_tcp->origin;
	format_ip_addr(hfi->tcp_info.ipaddr, sizeof(hfi->tcp_info.ipaddr), raw_hfi_info_tcp->ip_address);
	hfi->tcp_info.subnet_mask_prefix = raw_hfi_info_tcp->subnet_mask_prefix;
	format_ip_addr(hfi->tcp_info.gateway_ipaddr, sizeof(hfi->tcp_info.ipaddr), raw_hfi_info_tcp->ip_gateway);
	hfi->tcp_info.route_metric = raw_hfi_info_tcp->route_metric;
	format_ip_addr(hfi->tcp_info.primary_dns_ipaddr, sizeof(hfi->tcp_info.primary_dns_ipaddr), raw_hfi_info_tcp->primary_dns);
	format_ip_addr(hfi->tcp_info.secondary_dns_ipaddr, sizeof(hfi->tcp_info.secondary_dns_ipaddr), raw_hfi_info_tcp->secondary_dns);
	format_ip_addr(hfi->tcp_info.dhcp_server_ipaddr, sizeof(hfi->tcp_info.dhcp_server_ipaddr), raw_hfi_info_tcp->dhcp_server);
	if (get_and_verify_heap_ptr(raw_hfi_info_tcp, host_name, 1, &hfi->tcp_info.hostname_from_dhcp))
		return -EINVAL;
	if (raw_hfi_info_tcp->transport_flags & (1 << HFIINFOTCPFLAG_DHCP_OVERRIDE))
		hfi->tcp_info.info_is_from_dhcp = true;
	if (raw_hfi_info_tcp->transport_flags & (1 << HFIINFOTCPFLAG_GLOBAL_ROUTE_VS_LINK_LOCAL_OVERRIDE))
		hfi->tcp_info.this_hfi_is_default_route = true;
	if (raw_hfi_info_tcp->transport_flags & (1 << HFIINFOTCPFLAG_OEM_EXTENDED_ADAPTER_INFO)) {
		struct raw_nbft_hfi_info_tcp_extended_info *hfi_info_tcp_extended_info;

		if (!in_heap(header, raw_hfi_info_tcp->extended_adapter_info_length, raw_hfi_info_tcp->extended_adapter_info_offset)) {
			nvme_msg(NULL, LOG_DEBUG, "file %s: extended_adapter_info structure has invalid offset or length\n", nbft->filename);
			return -EINVAL;
		}
		hfi_info_tcp_extended_info = (struct raw_nbft_hfi_info_tcp_extended_info *)(nbft->raw_nbft + raw_hfi_info_tcp->extended_adapter_info_offset);

		// could verify structure ID, version, length, HFI index here
		if (hfi_info_tcp_extended_info->extended_capabilities & (1 << HFIINFOTCPEXTENDEDCAP_TRANSPORT_OFFLOAD))
			hfi->tcp_info.transport_offload_supported = true;
	}
	return 0;
}

static int read_hfi(struct nbft_info *nbft, struct raw_nbft_hfi *raw_hfi, struct nbft_hfi **h)
{
	int ret;
	struct nbft_hfi *hfi;
	struct raw_nbft_header *header;

	if (!(raw_hfi->hfi_flags & (1 << HFIFLAG_BLOCK_VALID)))
		return -EINVAL;

	hfi = calloc(1, sizeof(struct nbft_hfi));
	if (!hfi) {
		return -ENOMEM;
	}

	header = (struct raw_nbft_header *)nbft->raw_nbft;

	hfi->index = raw_hfi->index;
	if (raw_hfi->hfi_flags & (1 << HFIFLAG_HOSTID_OVERRIDE)) {
		if ((raw_hfi->hostid_length != 16) && (raw_hfi->hostid_length != 0)) {
			nvme_msg(NULL, LOG_DEBUG, "file %s: length of host id in hfi is invalid\n", nbft->filename);
			ret = -EINVAL;
			goto fail;
		}
		if (get_and_verify_heap_ptr(raw_hfi, hostid, 0, (char **)&hfi->host_id)) {
			ret = -EINVAL;
			goto fail;
		}
	}
	if (raw_hfi->hfi_flags & (1 << HFIFLAG_HOSTNQN_OVERRIDE))
		if (get_and_verify_heap_ptr(raw_hfi, hostnqn, 1, &hfi->host_nqn)) {
			ret = -EINVAL;
			goto fail;
		}

	/*
	 * read HFI_INFO for this HFI
	 */
	if (raw_hfi->hfi_transport_type == 1) {
		/*
		 * tcp
		 */
		struct raw_nbft_hfi_info_tcp *raw_hfi_info_tcp;

		strncpy(hfi->transport, trtype_to_string(raw_hfi->hfi_transport_type), sizeof(hfi->transport));

		if (!in_heap(header, raw_hfi->info_structure_length, raw_hfi->info_structure_offset)) {
			nvme_msg(NULL, LOG_DEBUG, "file %s: hfi_info structure has invalid offset or length\n", nbft->filename);
			ret = -EINVAL;
			goto fail;
		}
		raw_hfi_info_tcp = (struct raw_nbft_hfi_info_tcp *)(nbft->raw_nbft + raw_hfi->info_structure_offset);
		ret = read_hfi_info_tcp(nbft, raw_hfi_info_tcp, hfi);
		if (ret)
			goto fail;
	} else {
		ret = -EINVAL;
		goto fail;
	}

	*h = hfi;
	return 0;

fail:
	free(hfi);
	return ret;
}

static int read_discovery(struct nbft_info *nbft, struct raw_nbft_discovery *raw_discovery, struct nbft_discovery **d)
{
	int ret;
	struct nbft_discovery *discovery;
	struct raw_nbft_header *header;

	header = (struct raw_nbft_header *)nbft->raw_nbft;

	if (!(raw_discovery->discovery_structure_flags & (1 << DISCOVERYFLAGS_BLOCK_VALID)))
		return -EINVAL;

	discovery = calloc(1, sizeof(struct nbft_discovery));
	if (!discovery) {
		ret = -ENOMEM;
		goto discovery_fail;
	}

	discovery->index = raw_discovery->index;

	if (get_and_verify_heap_ptr(raw_discovery, discovery_ctrl_addr, 1, &discovery->uri))
		return -EINVAL;

	if (get_and_verify_heap_ptr(raw_discovery, discovery_controller_nqn, 1, &discovery->nqn))
		return -EINVAL;

	discovery->hfi = hfi_index(nbft, raw_discovery->discovery_record_hfi);
	if (raw_discovery->discovery_record_hfi && !discovery->hfi)
		nvme_msg(NULL, LOG_DEBUG, "file %s: discovery %d HFI not found\n",
			nbft->filename, discovery->index);

	discovery->security = security_index(nbft, raw_discovery->discovery_record_security_profile);
	if (raw_discovery->discovery_record_security_profile && !discovery->security)
		nvme_msg(NULL, LOG_DEBUG, "file %s: discovery %d security profile not found\n",
			nbft->filename, discovery->index);

	*d = discovery;
	return 0;

discovery_fail:
	free(discovery);
	return ret;
}

static int read_security(struct nbft_info *nbft, struct raw_nbft_security *raw_security, struct nbft_security **s)
{
	/*
	 *  TODO add security stuff
	 */
	return -EINVAL;
}

static void read_hfi_structures(struct nbft_info *nbft, int num_hfi, struct raw_nbft_hfi *raw_hfi_array)
{
	int c;

	for (c = 0; c < num_hfi; c++) {
		struct raw_nbft_hfi *raw_hfi = &raw_hfi_array[c];
		struct nbft_hfi *hfi;

		if (read_hfi(nbft, raw_hfi, &hfi) == 0)
			list_add_tail(&nbft->hfi_list, &hfi->node);
	}
}

static void read_security_structures(struct nbft_info *nbft, int num_security_profiles, struct raw_nbft_security *raw_security_array)
{
	int c;

	for (c = 0; c < num_security_profiles; c++) {
		struct raw_nbft_security *raw_security = &raw_security_array[c];
		struct nbft_security *security;

		if (read_security(nbft, raw_security, &security) == 0)
			list_add_tail(&nbft->security_list, &security->node);
	}
}

static void read_discovery_structures(struct nbft_info *nbft, int num_discovery_entries, struct raw_nbft_discovery *raw_discovery_array)
{
	int c;

	for (c = 0; c < num_discovery_entries; c++) {
		struct raw_nbft_discovery *raw_discovery = &raw_discovery_array[c];
		struct nbft_discovery *discovery;

		if (read_discovery(nbft, raw_discovery, &discovery) == 0)
			list_add_tail(&nbft->discovery_list, &discovery->node);
	}
}

static void read_snss_structures(struct nbft_info *nbft, int number_of_namespaces, struct raw_nbft_snss *raw_snss_array)
{
	int c;

	for (c = 0; c < number_of_namespaces; c++) {
		struct raw_nbft_snss *raw_snss = &raw_snss_array[c];
		struct nbft_subsystem_ns *ss;

		if (read_snss(nbft, raw_snss, &ss) == 0)
			list_add_tail(&nbft->subsystem_ns_list, &ss->node);
	}
}

static int parse_raw_nbft(struct nbft_info *nbft)
{
	__u8 *raw_nbft = nbft->raw_nbft;
	int raw_nbft_size = nbft->raw_nbft_size;

	struct raw_nbft_header *header;
	struct raw_nbft_control *control;
	struct raw_nbft_host *host;
	struct raw_nbft_hfi *raw_hfi_array = NULL;
	struct raw_nbft_snss *raw_snss_array = NULL;
	struct raw_nbft_security *raw_security_array = NULL;
	struct raw_nbft_discovery *raw_discovery_array = NULL;

	verify(raw_nbft_size >= sizeof(struct raw_nbft_header) + sizeof(struct raw_nbft_control),
	       "table is too short");
	verify(csum(raw_nbft, raw_nbft_size) == 0, "invalid checksum");

	/*
	 * header
	 */
	header = (struct raw_nbft_header *)raw_nbft;

	verify(strncmp(header->signature, NBFT_ACPI_SIG, 4) == 0, "invalid signature");
	verify(header->length <= raw_nbft_size, "length in header exceeds table length");
	verify(header->revision == 1, "unsupported revision");
	verify(header->heap_length + header->heap_offset <= header->length,
	       "heap exceeds table length");

	/*
	 * control
	 */
	control = (struct raw_nbft_control *)(raw_nbft + sizeof(struct raw_nbft_header));

	verify(control->structure_id == NBFT_CONTROL, "invalid ID in control structure");

	if ((control->flags & (1 << CONTROLFLAG_BLOCK_VALID)) == 0)
		return 0;

	/*
	 * host
	 */
	verify(control->host_structure_offset + sizeof(struct raw_nbft_host) <= header->length &&
	       control->host_structure_offset > 0,
	       "host structure offset/length is invalid");
	host = (struct raw_nbft_host *)(raw_nbft + control->host_structure_offset);
	nbft->host.id = &(host->host_identifier);
	if (get_and_verify_heap_ptr(host, host_nqn, 1, &nbft->host.nqn) != 0)
		return -EINVAL;

	/*
	 * HFI
	 */
	if (control->num_hfi > 0) {
		verify(control->hfi_1_offset + sizeof(struct raw_nbft_hfi) * control->num_hfi <= header->length,
		       "invalid hfi structure offset");
		raw_hfi_array = (struct raw_nbft_hfi *)(raw_nbft + control->hfi_1_offset);
		read_hfi_structures(nbft, control->num_hfi, raw_hfi_array);
	}

	/*
	 * security
	 */
	if (control->num_security_profiles > 0) {
		verify(control->security_profile_1_offset + sizeof(struct raw_nbft_security) * control->num_security_profiles <= header->length,
		       "invalid security structure offset");
		raw_security_array = (struct raw_nbft_security *)(raw_nbft + control->security_profile_1_offset);
		read_security_structures(nbft, control->num_security_profiles, raw_security_array);
	}

	/*
	 * discovery
	 */
	if (control->num_discovery_entries > 0) {
		verify(control->discovery_structure_1_offset + sizeof(struct raw_nbft_discovery) * control->num_discovery_entries <= header->length,
		       "invalid discovery structure offset");
		raw_discovery_array = (struct raw_nbft_discovery *)(raw_nbft + control->discovery_structure_1_offset);
		read_discovery_structures(nbft, control->num_discovery_entries, raw_discovery_array);
	}

	/*
	 * subsystem namespace
	 */
	if (control->number_of_namespaces > 0) {
		verify(control->namespace_1_offset + sizeof(struct raw_nbft_snss) * control->number_of_namespaces <= header->length,
		       "invalid subsystem namespace structure offset");
		raw_snss_array = (struct raw_nbft_snss *)(raw_nbft + control->namespace_1_offset);
		read_snss_structures(nbft, control->number_of_namespaces, raw_snss_array);
	}

	return 0;
}

void nbft_free(struct nbft_info *nbft)
{
	void *subtable;
	struct nbft_subsystem_ns *ns;

	while ((subtable = list_pop(&nbft->hfi_list, struct nbft_hfi, node)))
		free(subtable);
	while ((subtable = list_pop(&nbft->discovery_list, struct nbft_discovery, node)))
		free(subtable);
	while ((subtable = list_pop(&nbft->security_list, struct nbft_security, node)))
		free(subtable);
	while ((ns = list_pop(&nbft->subsystem_ns_list, struct nbft_subsystem_ns, node))) {
		free(ns->hfis);
		free(ns);
	}
	free(nbft->raw_nbft);
	free(nbft);
}

int nbft_read(struct nbft_info **nbft, const char *filename)
{
	__u8 *raw_nbft = NULL;
	size_t raw_nbft_size;
	FILE *raw_nbft_fp;
	int i, ret = 0;

	/*
	 * read in raw nbft file
	 */
	raw_nbft_fp = fopen(filename, "rb");
	if (raw_nbft_fp == NULL) {
		nvme_msg(NULL, LOG_ERR, "Failed to open %s: %s\n", filename, strerror(errno));
		return -EINVAL;
	}

	i = fseek(raw_nbft_fp, 0L, SEEK_END);
	if (i) {
		nvme_msg(NULL, LOG_ERR, "Failed to read from %s: %s\n", filename, strerror(errno));
		ret = -EINVAL;
		goto fail_1;
	}

	raw_nbft_size = ftell(raw_nbft_fp);
	rewind(raw_nbft_fp);

	raw_nbft = malloc(raw_nbft_size);
	if (!raw_nbft) {
		nvme_msg(NULL, LOG_ERR, "Failed to allocate memory for NBFT table");
		ret = -ENOMEM;
		goto fail_1;
	}

	i = fread(raw_nbft, sizeof(*raw_nbft), raw_nbft_size, raw_nbft_fp);
	if (i != raw_nbft_size) {
		nvme_msg(NULL, LOG_ERR, "Failed to read from %s: %s\n", filename, strerror(errno));
		ret = -EINVAL;
		goto fail_1;
	}
	fclose(raw_nbft_fp);

	/*
	 * alloc new struct nbft_info, add raw nbft & filename to it, and add it to the list
	 */
	*nbft = calloc(1, sizeof(struct nbft_info));
	if (!*nbft) {
		nvme_msg(NULL, LOG_ERR, "Could not allocate memory for NBFT\n");
		ret = -ENOMEM;
		goto fail_2;
	}

	strncpy((*nbft)->filename, filename, sizeof((*nbft)->filename) - 1);
	(*nbft)->raw_nbft = raw_nbft;
	(*nbft)->raw_nbft_size = raw_nbft_size;
	list_head_init(&(*nbft)->hfi_list);
	list_head_init(&(*nbft)->security_list);
	list_head_init(&(*nbft)->discovery_list);
	list_head_init(&(*nbft)->subsystem_ns_list);

	if (parse_raw_nbft(*nbft)) {
		nvme_msg(NULL, LOG_ERR, "Failed to parse %s\n", filename);
		nbft_free(*nbft);
		return -EINVAL;
	}
	return 0;

fail_1:
	fclose(raw_nbft_fp);
fail_2:
	free(raw_nbft);
	return ret;
}
