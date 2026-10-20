/**
 * @file radius_attributes.h
 * @brief Formatting and parsing of RADIUS attributes
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2022-2026 Oryx Embedded SARL. All rights reserved.
 *
 * This file is part of CycloneEAP Open.
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
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.6.8
 **/

#ifndef _RADIUS_ATTRIBUTES_H
#define _RADIUS_ATTRIBUTES_H

//Dependencies
#include "radius/radius.h"

//Maximum length of attribute value
#define RADIUS_MAX_ATTR_VALUE_LEN 253

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Attribute types
 **/

typedef enum
{
   RADIUS_ATTR_USER_NAME                       = 1,   ///<User-Name
   RADIUS_ATTR_USER_PASSWORD                   = 2,   ///<User-Password
   RADIUS_ATTR_CHAP_PASSWORD                   = 3,   ///<CHAP-Password
   RADIUS_ATTR_NAS_IP_ADDR                     = 4,   ///<NAS-IP-Address
   RADIUS_ATTR_NAS_PORT                        = 5,   ///<NAS-Port
   RADIUS_ATTR_SERVICE_TYPE                    = 6,   ///<Service-Type
   RADIUS_ATTR_FRAMED_PROTOCOL                 = 7,   ///<Framed-Protocol
   RADIUS_ATTR_FRAMED_IP_ADDR                  = 8,   ///<Framed-IP-Address
   RADIUS_ATTR_FRAMED_IP_NETMASK               = 9,   ///<Framed-IP-Netmask
   RADIUS_ATTR_FRAMED_ROUTING                  = 10,  ///<Framed-Routing
   RADIUS_ATTR_FILTER_ID                       = 11,  ///<Filter-Id
   RADIUS_ATTR_FRAMED_MTU                      = 12,  ///<Framed-MTU
   RADIUS_ATTR_FRAMED_COMPRESSION              = 13,  ///<Framed-Compression
   RADIUS_ATTR_LOGIN_IP_HOST                   = 14,  ///<Login-IP-Host
   RADIUS_ATTR_LOGIN_SERVICE                   = 15,  ///<Login-Service
   RADIUS_ATTR_LOGIN_TCP_PORT                  = 16,  ///<Login-TCP-Port
   RADIUS_ATTR_REPLY_MESSAGE                   = 18,  ///<Reply-Message
   RADIUS_ATTR_CALLBACK_NUMBER                 = 19,  ///<Callback-Number
   RADIUS_ATTR_CALLBACK_ID                     = 20,  ///<Callback-Id
   RADIUS_ATTR_FRAMED_ROUTE                    = 22,  ///<Framed-Route
   RADIUS_ATTR_FRAMED_IPX_NETWORK              = 23,  ///<Framed-IPX-Network
   RADIUS_ATTR_STATE                           = 24,  ///<State
   RADIUS_ATTR_CLASS                           = 25,  ///<Class
   RADIUS_ATTR_VENDOR_SPECIFIC                 = 26,  ///<Vendor-Specific
   RADIUS_ATTR_SESSION_TIMEOUT                 = 27,  ///<Session-Timeout
   RADIUS_ATTR_IDLE_TIMEOUT                    = 28,  ///<Idle-Timeout
   RADIUS_ATTR_TERMINATION_ACTION              = 29,  ///<Termination-Action
   RADIUS_ATTR_CALLED_STATION_ID               = 30,  ///<Called-Station-Id
   RADIUS_ATTR_CALLING_STATION_ID              = 31,  ///<Calling-Station-Id
   RADIUS_ATTR_NAS_IDENTIFIER                  = 32,  ///<NAS-Identifier
   RADIUS_ATTR_PROXY_STATE                     = 33,  ///<Proxy-State
   RADIUS_ATTR_LOGIN_LAT_SERVICE               = 34,  ///<Login-LAT-Service
   RADIUS_ATTR_LOGIN_LAT_NODE                  = 35,  ///<Login-LAT-Node
   RADIUS_ATTR_LOGIN_LAT_GROUP                 = 36,  ///<Login-LAT-Group
   RADIUS_ATTR_FRAMED_APPLETALK_LINK           = 37,  ///<Framed-AppleTalk-Link
   RADIUS_ATTR_FRAMED_APPLETALK_NETWORK        = 38,  ///<Framed-AppleTalk-Network
   RADIUS_ATTR_FRAMED_APPLETALK_ZONE           = 39,  ///<Framed-AppleTalk-Zone
   RADIUS_ATTR_ACCT_STATUS_TYPE                = 40,  ///<Acct-Status-Type
   RADIUS_ATTR_ACCT_DELAY_TIME                 = 41,  ///<Acct-Delay-Time
   RADIUS_ATTR_ACCT_INPUT_OCTETS               = 42,  ///<Acct-Input-Octets
   RADIUS_ATTR_ACCT_OUTPUT_OCTETS              = 43,  ///<Acct-Output-Octets
   RADIUS_ATTR_ACCT_SESSION_ID                 = 44,  ///<Acct-Session-Id
   RADIUS_ATTR_ACCT_AUTHENTIC                  = 45,  ///<Acct-Authentic
   RADIUS_ATTR_ACCT_SESSION_TIME               = 46,  ///<Acct-Session-Time
   RADIUS_ATTR_ACCT_INPUT_PACKETS              = 47,  ///<Acct-Input-Packets
   RADIUS_ATTR_ACCT_OUTPUT_PACKETS             = 48,  ///<Acct-Output-Packets
   RADIUS_ATTR_ACCT_TERMINATE_CAUSE            = 49,  ///<Acct-Terminate-Cause
   RADIUS_ATTR_ACCT_MULTI_SESSION_ID           = 50,  ///<Acct-Multi-Session-Id
   RADIUS_ATTR_ACCT_LINK_COUNT                 = 51,  ///<Acct-Link-Count
   RADIUS_ATTR_ACCT_INPUT_GIGAWORDS            = 52,  ///<Acct-Input-Gigawords
   RADIUS_ATTR_ACCT_OUTPUT_GIGAWORDS           = 53,  ///<Acct-Output-Gigawords
   RADIUS_ATTR_EVENT_TIMESTAMP                 = 55,  ///<Event-Timestamp
   RADIUS_ATTR_EGRESS_VLANID                   = 56,  ///<Egress-VLANID
   RADIUS_ATTR_INGRESS_FILTERS                 = 57,  ///<Ingress-Filters
   RADIUS_ATTR_EGRESS_VLAN_NAME                = 58,  ///<Egress-VLAN-Name
   RADIUS_ATTR_USER_PRIORITY_TABLE             = 59,  ///<User-Priority-Table
   RADIUS_ATTR_CHAP_CHALLENGE                  = 60,  ///<CHAP-Challenge
   RADIUS_ATTR_NAS_PORT_TYPE                   = 61,  ///<NAS-Port-Type
   RADIUS_ATTR_PORT_LIMIT                      = 62,  ///<Port-Limit
   RADIUS_ATTR_LOGIN_LAT_PORT                  = 63,  ///<Login-LAT-Port
   RADIUS_ATTR_TUNNEL_TYPE                     = 64,  ///<Tunnel-Type
   RADIUS_ATTR_TUNNEL_MEDIUM_TYPE              = 65,  ///<Tunnel-Medium-Type
   RADIUS_ATTR_TUNNEL_CLIENT_ENDPOINT          = 66,  ///<Tunnel-Client-Endpoint
   RADIUS_ATTR_TUNNEL_SERVER_ENDPOINT          = 67,  ///<Tunnel-Server-Endpoint
   RADIUS_ATTR_ACCT_TUNNEL_CONNECTION          = 68,  ///<Acct-Tunnel-Connection
   RADIUS_ATTR_TUNNEL_PASSWORD                 = 69,  ///<Tunnel-Password
   RADIUS_ATTR_ARAP_PASSWORD                   = 70,  ///<ARAP-Password
   RADIUS_ATTR_ARAP_FEATURES                   = 71,  ///<ARAP-Features
   RADIUS_ATTR_ARAP_ZONE_ACCESS                = 72,  ///<ARAP-Zone-Access
   RADIUS_ATTR_ARAP_SECURITY                   = 73,  ///<ARAP-Security
   RADIUS_ATTR_ARAP_SECURITY_DATA              = 74,  ///<ARAP-Security-Data
   RADIUS_ATTR_PASSWORD_RETRY                  = 75,  ///<Password-Retry
   RADIUS_ATTR_PROMPT                          = 76,  ///<Prompt
   RADIUS_ATTR_CONNECT_INFO                    = 77,  ///<Connect-Info
   RADIUS_ATTR_CONFIGURATION_TOKEN             = 78,  ///<Configuration-Token
   RADIUS_ATTR_EAP_MESSAGE                     = 79,  ///<EAP-Message
   RADIUS_ATTR_MESSAGE_AUTHENTICATOR           = 80,  ///<Message-Authenticator
   RADIUS_ATTR_TUNNEL_PRIVATE_GROUP_ID         = 81,  ///<Tunnel-Private-Group-ID
   RADIUS_ATTR_TUNNEL_ASSIGNMENT_ID            = 82,  ///<Tunnel-Assignment-ID
   RADIUS_ATTR_TUNNEL_PREFERENCE               = 83,  ///<Tunnel-Preference
   RADIUS_ATTR_ARAP_CHALLENGE_RESPONSE         = 84,  ///<ARAP-Challenge-Response
   RADIUS_ATTR_ACCT_INTERIM_INTERVAL           = 85,  ///<Acct-Interim-Interval
   RADIUS_ATTR_ACCT_TUNNEL_PACKETS_LOST        = 86,  ///<Acct-Tunnel-Packets-Lost
   RADIUS_ATTR_NAS_PORT_ID                     = 87,  ///<NAS-Port-Id
   RADIUS_ATTR_FRAMED_POOL                     = 88,  ///<Framed-Pool
   RADIUS_ATTR_CUI                             = 89,  ///<CUI
   RADIUS_ATTR_TUNNEL_CLIENT_AUTH_ID           = 90,  ///<Tunnel-Client-Auth-ID
   RADIUS_ATTR_TUNNEL_SERVER_AUTH_ID           = 91,  ///<Tunnel-Server-Auth-ID
   RADIUS_ATTR_NAS_FILTER_RULE                 = 92,  ///<NAS-Filter-Rule
   RADIUS_ATTR_ORIGINATING_LINE_INFO           = 94,  ///<Originating-Line-Info
   RADIUS_ATTR_NAS_IPV6_ADDR                   = 95,  ///<NAS-IPv6-Address
   RADIUS_ATTR_FRAMED_INTERFACE_ID             = 96,  ///<Framed-Interface-Id
   RADIUS_ATTR_FRAMED_IPV6_PREFIX              = 97,  ///<Framed-IPv6-Prefix
   RADIUS_ATTR_LOGIN_IPV6_HOST                 = 98,  ///<Login-IPv6-Host
   RADIUS_ATTR_FRAMED_IPV6_ROUTE               = 99,  ///<Framed-IPv6-Route
   RADIUS_ATTR_FRAMED_IPV6_POOL                = 100, ///<Framed-IPv6-Pool
   RADIUS_ATTR_ERROR_CAUSE                     = 101, ///<Error-Cause
   RADIUS_ATTR_EAP_KEY_NAME                    = 102, ///<EAP-Key-Name
   RADIUS_ATTR_DIGEST_RESPONSE                 = 103, ///<Digest-Response
   RADIUS_ATTR_DIGEST_REALM                    = 104, ///<Digest-Realm
   RADIUS_ATTR_DIGEST_NONCE                    = 105, ///<Digest-Nonce
   RADIUS_ATTR_DIGEST_RESPONSE_AUTH            = 106, ///<Digest-Response-Auth
   RADIUS_ATTR_DIGEST_NEXTNONCE                = 107, ///<Digest-Nextnonce
   RADIUS_ATTR_DIGEST_METHOD                   = 108, ///<Digest-Method
   RADIUS_ATTR_DIGEST_URI                      = 109, ///<Digest-URI
   RADIUS_ATTR_DIGEST_QOP                      = 110, ///<Digest-Qop
   RADIUS_ATTR_DIGEST_ALGORITHM                = 111, ///<Digest-Algorithm
   RADIUS_ATTR_DIGEST_ENTITY_BODY_HASH         = 112, ///<Digest-Entity-Body-Hash
   RADIUS_ATTR_DIGEST_CNONCE                   = 113, ///<Digest-CNonce
   RADIUS_ATTR_DIGEST_NONCE_COUNT              = 114, ///<Digest-Nonce-Count
   RADIUS_ATTR_DIGEST_USERNAME                 = 115, ///<Digest-Username
   RADIUS_ATTR_DIGEST_OPAQUE                   = 116, ///<Digest-Opaque
   RADIUS_ATTR_DIGEST_AUTH_PARAM               = 117, ///<Digest-Auth-Param
   RADIUS_ATTR_DIGEST_AKA_AUTS                 = 118, ///<Digest-AKA-Auts
   RADIUS_ATTR_DIGEST_DOMAIN                   = 119, ///<Digest-Domain
   RADIUS_ATTR_DIGEST_STALE                    = 120, ///<Digest-Stale
   RADIUS_ATTR_DIGEST_HA1                      = 121, ///<Digest-HA1
   RADIUS_ATTR_SIP_AOR                         = 122, ///<SIP-AOR
   RADIUS_ATTR_DELEGATED_IPV6_PREFIX           = 123, ///<Delegated-IPv6-Prefix
   RADIUS_ATTR_MIP6_FEATURE_VECTOR             = 124, ///<MIP6-Feature-Vector
   RADIUS_ATTR_MIP6_HOME_LINK_PREFIX           = 125, ///<MIP6-Home-Link-Prefix
   RADIUS_ATTR_OPERATOR_NAME                   = 126, ///<Operator-Name
   RADIUS_ATTR_LOCATION_INFORMATION            = 127, ///<Location-Information
   RADIUS_ATTR_LOCATION_DATA                   = 128, ///<Location-Data
   RADIUS_ATTR_BASIC_LOCATION_POLICY_RULES     = 129, ///<Basic-Location-Policy-Rules
   RADIUS_ATTR_EXTENDED_LOCATION_POLICY_RULES  = 130, ///<Extended-Location-Policy-Rules
   RADIUS_ATTR_LOCATION_CAPABLE                = 131, ///<Location-Capable
   RADIUS_ATTR_REQUESTED_LOCATION_INFO         = 132, ///<Requested-Location-Info
   RADIUS_ATTR_FRAMED_MANAGEMENT_PROTOCOL      = 133, ///<Framed-Management-Protocol
   RADIUS_ATTR_MANAGEMENT_TRANSPORT_PROTECTION = 134, ///<Management-Transport-Protection
   RADIUS_ATTR_MANAGEMENT_POLICY_ID            = 135, ///<Management-Policy-Id
   RADIUS_ATTR_MANAGEMENT_PRIVILEGE_LEVEL      = 136, ///<Management-Privilege-Level
   RADIUS_ATTR_PKM_SS_CERT                     = 137, ///<PKM-SS-Cert
   RADIUS_ATTR_PKM_CA_CERT                     = 138, ///<PKM-CA-Cert
   RADIUS_ATTR_PKM_CONFIG_SETTINGS             = 139, ///<PKM-Config-Settings
   RADIUS_ATTR_PKM_CRYPTOSUITE_LIST            = 140, ///<PKM-Cryptosuite-List
   RADIUS_ATTR_PKM_SAID                        = 141, ///<PKM-SAID
   RADIUS_ATTR_PKM_SA_DESCRIPTOR               = 142, ///<PKM-SA-Descriptor
   RADIUS_ATTR_PKM_AUTH_KEY                    = 143, ///<PKM-Auth-Key
   RADIUS_ATTR_DS_LITE_TUNNEL_NAME             = 144, ///<DS-Lite-Tunnel-Name
   RADIUS_ATTR_MOBILE_NODE_IDENTIFIER          = 145, ///<Mobile-Node-Identifier
   RADIUS_ATTR_SERVICE_SELECTION               = 146, ///<Service-Selection
   RADIUS_ATTR_PMIP6_HOME_LMA_IPV6_ADDR        = 147, ///<PMIP6-Home-LMA-IPv6-Address
   RADIUS_ATTR_PMIP6_VISITED_LMA_IPV6_ADDR     = 148, ///<PMIP6-Visited-LMA-IPv6-Address
   RADIUS_ATTR_PMIP6_HOME_LMA_IPV4_ADDR        = 149, ///<PMIP6-Home-LMA-IPv4-Address
   RADIUS_ATTR_PMIP6_VISITED_LMA_IPV4_ADDR     = 150, ///<PMIP6-Visited-LMA-IPv4-Address
   RADIUS_ATTR_PMIP6_HOME_HN_PREFIX            = 151, ///<PMIP6-Home-HN-Prefix
   RADIUS_ATTR_PMIP6_VISITED_HN_PREFIX         = 152, ///<PMIP6-Visited-HN-Prefix
   RADIUS_ATTR_PMIP6_HOME_INTERFACE_ID         = 153, ///<PMIP6-Home-Interface-ID
   RADIUS_ATTR_PMIP6_VISITED_INTERFACE_ID      = 154, ///<PMIP6-Visited-Interface-ID
   RADIUS_ATTR_PMIP6_HOME_IPV4_HOA             = 155, ///<PMIP6-Home-IPv4-HoA
   RADIUS_ATTR_PMIP6_VISITED_IPV4_HOA          = 156, ///<PMIP6-Visited-IPv4-HoA
   RADIUS_ATTR_PMIP6_HOME_DHCP4_SERVER_ADDR    = 157, ///<PMIP6-Home-DHCP4-Server-Address
   RADIUS_ATTR_PMIP6_VISITED_DHCP4_SERVER_ADDR = 158, ///<PMIP6-Visited-DHCP4-Server-Address
   RADIUS_ATTR_PMIP6_HOME_DHCP6_SERVER_ADDR    = 159, ///<PMIP6-Home-DHCP6-Server-Address
   RADIUS_ATTR_PMIP6_VISITED_DHCP6_SERVER_ADDR = 160, ///<PMIP6-Visited-DHCP6-Server-Address
   RADIUS_ATTR_PMIP6_HOME_IPV4_GATEWAY         = 161, ///<PMIP6-Home-IPv4-Gateway
   RADIUS_ATTR_PMIP6_VISITED_IPV4_GATEWAY      = 162, ///<PMIP6-Visited-IPv4-Gateway
   RADIUS_ATTR_EAP_LOWER_LAYER                 = 163, ///<EAP-Lower-Layer
   RADIUS_ATTR_GSS_ACCEPTOR_SERVICE_NAME       = 164, ///<GSS-Acceptor-Service-Name
   RADIUS_ATTR_GSS_ACCEPTOR_HOST_NAME          = 165, ///<GSS-Acceptor-Host-Name
   RADIUS_ATTR_GSS_ACCEPTOR_SERVICE_SPECIFICS  = 166, ///<GSS-Acceptor-Service-Specifics
   RADIUS_ATTR_GSS_ACCEPTOR_REALM_NAME         = 167, ///<GSS-Acceptor-Realm-Name
   RADIUS_ATTR_FRAMED_IPV6_ADDR                = 168, ///<Framed-IPv6-Address
   RADIUS_ATTR_DNS_SERVER_IPV6_ADDR            = 169, ///<DNS-Server-IPv6-Address
   RADIUS_ATTR_ROUTE_IPV6_INFORMATION          = 170, ///<Route-IPv6-Information
   RADIUS_ATTR_DELEGATED_IPV6_PREFIX_POOL      = 171, ///<Delegated-IPv6-Prefix-Pool
   RADIUS_ATTR_STATEFUL_IPV6_ADDR_POOL         = 172, ///<Stateful-IPv6-Address-Pool
   RADIUS_ATTR_IPV6_6RD_CONFIGURATION          = 173, ///<IPv6-6rd-Configuration
   RADIUS_ATTR_ALLOWED_CALLED_STATION_ID       = 174, ///<Allowed-Called-Station-Id
   RADIUS_ATTR_EAP_PEER_ID                     = 175, ///<EAP-Peer-Id
   RADIUS_ATTR_EAP_SERVER_ID                   = 176, ///<EAP-Server-Id
   RADIUS_ATTR_MOBILITY_DOMAIN_ID              = 177, ///<Mobility-Domain-Id
   RADIUS_ATTR_PREAUTH_TIMEOUT                 = 178, ///<Preauth-Timeout
   RADIUS_ATTR_NETWORK_ID_NAME                 = 179, ///<Network-Id-Name
   RADIUS_ATTR_EAPOL_ANNOUNCEMENT              = 180, ///<EAPoL-Announcement
   RADIUS_ATTR_WLAN_HESSID                     = 181, ///<WLAN-HESSID
   RADIUS_ATTR_WLAN_VENUE_INFO                 = 182, ///<WLAN-Venue-Info
   RADIUS_ATTR_WLAN_VENUE_LANGUAGE             = 183, ///<WLAN-Venue-Language
   RADIUS_ATTR_WLAN_VENUE_NAME                 = 184, ///<WLAN-Venue-Name
   RADIUS_ATTR_WLAN_REASON_CODE                = 185, ///<WLAN-Reason-Code
   RADIUS_ATTR_WLAN_PAIRWISE_CIPHER            = 186, ///<WLAN-Pairwise-Cipher
   RADIUS_ATTR_WLAN_GROUP_CIPHER               = 187, ///<WLAN-Group-Cipher
   RADIUS_ATTR_WLAN_AKM_SUITE                  = 188, ///<WLAN-AKM-Suite
   RADIUS_ATTR_WLAN_GROUP_MGMT_CIPHER          = 189, ///<WLAN-Group-Mgmt-Cipher
   RADIUS_ATTR_WLAN_RF_BAND                    = 190, ///<WLAN-RF-Band
   RADIUS_ATTR_EXTENDED_ATTR_1                 = 241, ///<Extended-Attribute-1
   RADIUS_ATTR_EXTENDED_ATTR_2                 = 242, ///<Extended-Attribute-2
   RADIUS_ATTR_EXTENDED_ATTR_3                 = 243, ///<Extended-Attribute-3
   RADIUS_ATTR_EXTENDED_ATTR_4                 = 244, ///<Extended-Attribute-4
   RADIUS_ATTR_EXTENDED_ATTR_5                 = 245, ///<Extended-Attribute-5
   RADIUS_ATTR_EXTENDED_ATTR_6                 = 246  ///<Extended-Attribute-6
} RadiusAttributeType;


/**
 * @brief Service types
 **/

typedef enum
{
   RADIUS_SERVICE_TYPE_LOGIN                   = 1,  ///<Login
   RADIUS_SERVICE_TYPE_FRAMED                  = 2,  ///<Framed
   RADIUS_SERVICE_TYPE_CALLBACK_LOGIN          = 3,  ///<Callback Login
   RADIUS_SERVICE_TYPE_CALLBACK_FRAMED         = 4,  ///<Callback Framed
   RADIUS_SERVICE_TYPE_OUTBOUND                = 5,  ///<Outbound
   RADIUS_SERVICE_TYPE_ADMINISTRATIVE          = 6,  ///<Administrative
   RADIUS_SERVICE_TYPE_NAS_PROMPT              = 7,  ///<NAS Prompt
   RADIUS_SERVICE_TYPE_AUTHENTICATE_ONLY       = 8,  ///<Authenticate Only
   RADIUS_SERVICE_TYPE_CALLBACK_NAS_PROMPT     = 9,  ///<Callback NAS Prompt
   RADIUS_SERVICE_TYPE_CALL_CHECK              = 10, ///<Call Check
   RADIUS_SERVICE_TYPE_CALLBACK_ADMINISTRATIVE = 11  ///<Callback Administrative
} RadiusServiceType;

/**
 * @brief Service types
 **/

typedef enum
{
   RADIUS_PORT_TYPE_ASYNC                = 0,  ///<Async
   RADIUS_PORT_TYPE_SYNC                 = 1,  ///<Sync
   RADIUS_PORT_TYPE_ISDN_SYNC            = 2,  ///<ISDN Sync
   RADIUS_PORT_TYPE_ISDN_ASYNC_V120      = 3,  ///<ISDN Async V.120
   RADIUS_PORT_TYPE_ISDN_ASYNC_V110      = 4,  ///<ISDN Async V.110
   RADIUS_PORT_TYPE_VIRTUAL              = 5,  ///<Virtual
   RADIUS_PORT_TYPE_PIAFS                = 6,  ///<PIAFS
   RADIUS_PORT_TYPE_HDLC_CLEAR_CHANNEL   = 7,  ///<HDLC Clear Channel
   RADIUS_PORT_TYPE_X25                  = 8,  ///<X.25
   RADIUS_PORT_TYPE_X75                  = 9,  ///<X.75
   RADIUS_PORT_TYPE_G3_FAX               = 10, ///<G.3 Fax
   RADIUS_PORT_TYPE_SDSL                 = 11, ///<SDSL
   RADIUS_PORT_TYPE_ADSL_CAP             = 12, ///<ADSL-CAP
   RADIUS_PORT_TYPE_ADSL_DMT             = 13, ///<ADSL-DMT
   RADIUS_PORT_TYPE_IDSL                 = 14, ///<IDSL
   RADIUS_PORT_TYPE_ETHERNET             = 15, ///<Ethernet
   RADIUS_PORT_TYPE_XDSL                 = 16, ///<xDSL
   RADIUS_PORT_TYPE_CABLE                = 17, ///<Cable
   RADIUS_PORT_TYPE_WIRELESS_OTHER       = 18, ///<Wireless - Other
   RADIUS_PORT_TYPE_WIRELESS_IEEE_802_11 = 19  ///<Wireless - IEEE 802.11
} RadiusPortType;


//CC-RX, CodeWarrior or Win32 compiler?
#if defined(__CCRX__)
   #pragma pack
#elif defined(__CWCC__) || defined(_WIN32)
   #pragma pack(push, 1)
#endif


/**
 * @brief Attribute
 **/

typedef __packed_struct
{
   uint8_t type;    //0
   uint8_t length;  //1
   uint8_t value[]; //2
} RadiusAttribute;


//CC-RX, CodeWarrior or Win32 compiler?
#if defined(__CCRX__)
   #pragma unpack
#elif defined(__CWCC__) || defined(_WIN32)
   #pragma pack(pop)
#endif

//RADIUS related functions
void radiusAddAttribute(RadiusPacket *packet, uint8_t type, const void *value,
   size_t length);

const RadiusAttribute *radiusGetAttribute(const RadiusPacket *packet,
   uint8_t type, uint_t index);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
