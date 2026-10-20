/**
 * @file radius_debug.c
 * @brief Data logging functions for debugging purpose (RADIUS)
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

//Switch to the appropriate trace level
#define TRACE_LEVEL RADIUS_TRACE_LEVEL

//Dependencies
#include "radius/radius.h"
#include "radius/radius_debug.h"
#include "debug.h"

//Check EAP library configuration
#if (RADIUS_SUPPORT == ENABLED && RADIUS_TRACE_LEVEL >= TRACE_LEVEL_DEBUG)

//RADIUS codes
static const RadiusParamName radiusCodeList[] =
{
   {RADIUS_CODE_ACCESS_REQUEST,      "Access-Request"},
   {RADIUS_CODE_ACCESS_ACCEPT,       "Access-Accept"},
   {RADIUS_CODE_ACCESS_REJECT,       "Access-Reject"},
   {RADIUS_CODE_ACCOUNTING_REQUEST,  "Accounting-Request"},
   {RADIUS_CODE_ACCOUNTING_RESPONSE, "Accounting-Response"},
   {RADIUS_CODE_ACCESS_CHALLENGE,    "Access-Challenge"},
   {RADIUS_CODE_STATUS_SERVER,       "Status-Server"},
   {RADIUS_CODE_STATUS_CLIENT,       "Status-Client"}
};

//RADIUS codes
static const RadiusParamName radiusAttrTypeList[] =
{
   {RADIUS_ATTR_USER_NAME,                        "User-Name"},
   {RADIUS_ATTR_USER_PASSWORD,                    "User-Password"},
   {RADIUS_ATTR_CHAP_PASSWORD,                    "CHAP-Password"},
   {RADIUS_ATTR_NAS_IP_ADDR,                      "NAS-IP-Address"},
   {RADIUS_ATTR_NAS_PORT,                         "NAS-Port"},
   {RADIUS_ATTR_SERVICE_TYPE,                     "Service-Type"},
   {RADIUS_ATTR_FRAMED_PROTOCOL,                  "Framed-Protocol"},
   {RADIUS_ATTR_FRAMED_IP_ADDR,                   "Framed-IP-Address"},
   {RADIUS_ATTR_FRAMED_IP_NETMASK,                "Framed-IP-Netmask"},
   {RADIUS_ATTR_FRAMED_ROUTING,                   "Framed-Routing"},
   {RADIUS_ATTR_FILTER_ID,                        "Filter-Id"},
   {RADIUS_ATTR_FRAMED_MTU,                       "Framed-MTU"},
   {RADIUS_ATTR_FRAMED_COMPRESSION,               "Framed-Compression"},
   {RADIUS_ATTR_LOGIN_IP_HOST,                    "Login-IP-Host"},
   {RADIUS_ATTR_LOGIN_SERVICE,                    "Login-Service"},
   {RADIUS_ATTR_LOGIN_TCP_PORT,                   "Login-TCP-Port"},
   {RADIUS_ATTR_REPLY_MESSAGE,                    "Reply-Message"},
   {RADIUS_ATTR_CALLBACK_NUMBER,                  "Callback-Number"},
   {RADIUS_ATTR_CALLBACK_ID,                      "Callback-Id"},
   {RADIUS_ATTR_FRAMED_ROUTE,                     "Framed-Route"},
   {RADIUS_ATTR_FRAMED_IPX_NETWORK,               "Framed-IPX-Network"},
   {RADIUS_ATTR_STATE,                            "State"},
   {RADIUS_ATTR_CLASS,                            "Class"},
   {RADIUS_ATTR_VENDOR_SPECIFIC,                  "Vendor-Specific"},
   {RADIUS_ATTR_SESSION_TIMEOUT,                  "Session-Timeout"},
   {RADIUS_ATTR_IDLE_TIMEOUT,                     "Idle-Timeout"},
   {RADIUS_ATTR_TERMINATION_ACTION,               "Termination-Action"},
   {RADIUS_ATTR_CALLED_STATION_ID,                "Called-Station-Id"},
   {RADIUS_ATTR_CALLING_STATION_ID,               "Calling-Station-Id"},
   {RADIUS_ATTR_NAS_IDENTIFIER,                   "NAS-Identifier"},
   {RADIUS_ATTR_PROXY_STATE,                      "Proxy-State"},
   {RADIUS_ATTR_LOGIN_LAT_SERVICE,                "Login-LAT-Service"},
   {RADIUS_ATTR_LOGIN_LAT_NODE,                   "Login-LAT-Node"},
   {RADIUS_ATTR_LOGIN_LAT_GROUP,                  "Login-LAT-Group"},
   {RADIUS_ATTR_FRAMED_APPLETALK_LINK,            "Framed-AppleTalk-Link"},
   {RADIUS_ATTR_FRAMED_APPLETALK_NETWORK,         "Framed-AppleTalk-Network"},
   {RADIUS_ATTR_FRAMED_APPLETALK_ZONE,            "Framed-AppleTalk-Zone"},
   {RADIUS_ATTR_ACCT_STATUS_TYPE,                 "Acct-Status-Type"},
   {RADIUS_ATTR_ACCT_DELAY_TIME,                  "Acct-Delay-Time"},
   {RADIUS_ATTR_ACCT_INPUT_OCTETS,                "Acct-Input-Octets"},
   {RADIUS_ATTR_ACCT_OUTPUT_OCTETS,               "Acct-Output-Octets"},
   {RADIUS_ATTR_ACCT_SESSION_ID,                  "Acct-Session-Id"},
   {RADIUS_ATTR_ACCT_AUTHENTIC,                   "Acct-Authentic"},
   {RADIUS_ATTR_ACCT_SESSION_TIME,                "Acct-Session-Time"},
   {RADIUS_ATTR_ACCT_INPUT_PACKETS,               "Acct-Input-Packets"},
   {RADIUS_ATTR_ACCT_OUTPUT_PACKETS,              "Acct-Output-Packets"},
   {RADIUS_ATTR_ACCT_TERMINATE_CAUSE,             "Acct-Terminate-Cause"},
   {RADIUS_ATTR_ACCT_MULTI_SESSION_ID,            "Acct-Multi-Session-Id"},
   {RADIUS_ATTR_ACCT_LINK_COUNT,                  "Acct-Link-Count"},
   {RADIUS_ATTR_ACCT_INPUT_GIGAWORDS,             "Acct-Input-Gigawords"},
   {RADIUS_ATTR_ACCT_OUTPUT_GIGAWORDS,            "Acct-Output-Gigawords"},
   {RADIUS_ATTR_EVENT_TIMESTAMP,                  "Event-Timestamp"},
   {RADIUS_ATTR_EGRESS_VLANID,                    "Egress-VLANID"},
   {RADIUS_ATTR_INGRESS_FILTERS,                  "Ingress-Filters"},
   {RADIUS_ATTR_EGRESS_VLAN_NAME,                 "Egress-VLAN-Name"},
   {RADIUS_ATTR_USER_PRIORITY_TABLE,              "User-Priority-Table"},
   {RADIUS_ATTR_CHAP_CHALLENGE,                   "CHAP-Challenge"},
   {RADIUS_ATTR_NAS_PORT_TYPE,                    "NAS-Port-Type"},
   {RADIUS_ATTR_PORT_LIMIT,                       "Port-Limit"},
   {RADIUS_ATTR_LOGIN_LAT_PORT,                   "Login-LAT-Port"},
   {RADIUS_ATTR_TUNNEL_TYPE,                      "Tunnel-Type"},
   {RADIUS_ATTR_TUNNEL_MEDIUM_TYPE,               "Tunnel-Medium-Type"},
   {RADIUS_ATTR_TUNNEL_CLIENT_ENDPOINT,           "Tunnel-Client-Endpoint"},
   {RADIUS_ATTR_TUNNEL_SERVER_ENDPOINT,           "Tunnel-Server-Endpoint"},
   {RADIUS_ATTR_ACCT_TUNNEL_CONNECTION,           "Acct-Tunnel-Connection"},
   {RADIUS_ATTR_TUNNEL_PASSWORD,                  "Tunnel-Password"},
   {RADIUS_ATTR_ARAP_PASSWORD,                    "ARAP-Password"},
   {RADIUS_ATTR_ARAP_FEATURES,                    "ARAP-Features"},
   {RADIUS_ATTR_ARAP_ZONE_ACCESS,                 "ARAP-Zone-Access"},
   {RADIUS_ATTR_ARAP_SECURITY,                    "ARAP-Security"},
   {RADIUS_ATTR_ARAP_SECURITY_DATA,               "ARAP-Security-Data"},
   {RADIUS_ATTR_PASSWORD_RETRY,                   "Password-Retry"},
   {RADIUS_ATTR_PROMPT,                           "Prompt"},
   {RADIUS_ATTR_CONNECT_INFO,                     "Connect-Info"},
   {RADIUS_ATTR_CONFIGURATION_TOKEN,              "Configuration-Token"},
   {RADIUS_ATTR_EAP_MESSAGE,                      "EAP-Message"},
   {RADIUS_ATTR_MESSAGE_AUTHENTICATOR,            "Message-Authenticator"},
   {RADIUS_ATTR_TUNNEL_PRIVATE_GROUP_ID,          "Tunnel-Private-Group-ID"},
   {RADIUS_ATTR_TUNNEL_ASSIGNMENT_ID,             "Tunnel-Assignment-ID"},
   {RADIUS_ATTR_TUNNEL_PREFERENCE,                "Tunnel-Preference"},
   {RADIUS_ATTR_ARAP_CHALLENGE_RESPONSE,          "ARAP-Challenge-Response"},
   {RADIUS_ATTR_ACCT_INTERIM_INTERVAL,            "Acct-Interim-Interval"},
   {RADIUS_ATTR_ACCT_TUNNEL_PACKETS_LOST,         "Acct-Tunnel-Packets-Lost"},
   {RADIUS_ATTR_NAS_PORT_ID,                      "NAS-Port-Id"},
   {RADIUS_ATTR_FRAMED_POOL,                      "Framed-Pool"},
   {RADIUS_ATTR_CUI,                              "CUI"},
   {RADIUS_ATTR_TUNNEL_CLIENT_AUTH_ID,            "Tunnel-Client-Auth-ID"},
   {RADIUS_ATTR_TUNNEL_SERVER_AUTH_ID,            "Tunnel-Server-Auth-ID"},
   {RADIUS_ATTR_NAS_FILTER_RULE,                  "NAS-Filter-Rule"},
   {RADIUS_ATTR_ORIGINATING_LINE_INFO,            "Originating-Line-Info"},
   {RADIUS_ATTR_NAS_IPV6_ADDR,                    "NAS-IPv6-Address"},
   {RADIUS_ATTR_FRAMED_INTERFACE_ID,              "Framed-Interface-Id"},
   {RADIUS_ATTR_FRAMED_IPV6_PREFIX,               "Framed-IPv6-Prefix"},
   {RADIUS_ATTR_LOGIN_IPV6_HOST,                  "Login-IPv6-Host"},
   {RADIUS_ATTR_FRAMED_IPV6_ROUTE,                "Framed-IPv6-Route"},
   {RADIUS_ATTR_FRAMED_IPV6_POOL,                 "Framed-IPv6-Pool"},
   {RADIUS_ATTR_ERROR_CAUSE,                      "Error-Cause"},
   {RADIUS_ATTR_EAP_KEY_NAME,                     "EAP-Key-Name"},
   {RADIUS_ATTR_DIGEST_RESPONSE,                  "Digest-Response"},
   {RADIUS_ATTR_DIGEST_REALM,                     "Digest-Realm"},
   {RADIUS_ATTR_DIGEST_NONCE,                     "Digest-Nonce"},
   {RADIUS_ATTR_DIGEST_RESPONSE_AUTH,             "Digest-Response-Auth"},
   {RADIUS_ATTR_DIGEST_NEXTNONCE,                 "Digest-Nextnonce"},
   {RADIUS_ATTR_DIGEST_METHOD,                    "Digest-Method"},
   {RADIUS_ATTR_DIGEST_URI,                       "Digest-URI"},
   {RADIUS_ATTR_DIGEST_QOP,                       "Digest-Qop"},
   {RADIUS_ATTR_DIGEST_ALGORITHM,                 "Digest-Algorithm"},
   {RADIUS_ATTR_DIGEST_ENTITY_BODY_HASH,          "Digest-Entity-Body-Hash"},
   {RADIUS_ATTR_DIGEST_CNONCE,                    "Digest-CNonce"},
   {RADIUS_ATTR_DIGEST_NONCE_COUNT,               "Digest-Nonce-Count"},
   {RADIUS_ATTR_DIGEST_USERNAME,                  "Digest-Username"},
   {RADIUS_ATTR_DIGEST_OPAQUE,                    "Digest-Opaque"},
   {RADIUS_ATTR_DIGEST_AUTH_PARAM,                "Digest-Auth-Param"},
   {RADIUS_ATTR_DIGEST_AKA_AUTS,                  "Digest-AKA-Auts"},
   {RADIUS_ATTR_DIGEST_DOMAIN,                    "Digest-Domain"},
   {RADIUS_ATTR_DIGEST_STALE,                     "Digest-Stale"},
   {RADIUS_ATTR_DIGEST_HA1,                       "Digest-HA1"},
   {RADIUS_ATTR_SIP_AOR,                          "SIP-AOR"},
   {RADIUS_ATTR_DELEGATED_IPV6_PREFIX,            "Delegated-IPv6-Prefix"},
   {RADIUS_ATTR_MIP6_FEATURE_VECTOR,              "MIP6-Feature-Vector"},
   {RADIUS_ATTR_MIP6_HOME_LINK_PREFIX,            "MIP6-Home-Link-Prefix"},
   {RADIUS_ATTR_OPERATOR_NAME,                    "Operator-Name"},
   {RADIUS_ATTR_LOCATION_INFORMATION,             "Location-Information"},
   {RADIUS_ATTR_LOCATION_DATA,                    "Location-Data"},
   {RADIUS_ATTR_BASIC_LOCATION_POLICY_RULES,      "Basic-Location-Policy-Rules"},
   {RADIUS_ATTR_EXTENDED_LOCATION_POLICY_RULES,   "Extended-Location-Policy-Rules"},
   {RADIUS_ATTR_LOCATION_CAPABLE,                 "Location-Capable"},
   {RADIUS_ATTR_REQUESTED_LOCATION_INFO,          "Requested-Location-Info"},
   {RADIUS_ATTR_FRAMED_MANAGEMENT_PROTOCOL,       "Framed-Management-Protocol"},
   {RADIUS_ATTR_MANAGEMENT_TRANSPORT_PROTECTION,  "Management-Transport-Protection"},
   {RADIUS_ATTR_MANAGEMENT_POLICY_ID,             "Management-Policy-Id"},
   {RADIUS_ATTR_MANAGEMENT_PRIVILEGE_LEVEL,       "Management-Privilege-Level"},
   {RADIUS_ATTR_PKM_SS_CERT,                      "PKM-SS-Cert"},
   {RADIUS_ATTR_PKM_CA_CERT,                      "PKM-CA-Cert"},
   {RADIUS_ATTR_PKM_CONFIG_SETTINGS,              "PKM-Config-Settings"},
   {RADIUS_ATTR_PKM_CRYPTOSUITE_LIST,             "PKM-Cryptosuite-List"},
   {RADIUS_ATTR_PKM_SAID,                         "PKM-SAID"},
   {RADIUS_ATTR_PKM_SA_DESCRIPTOR,                "PKM-SA-Descriptor"},
   {RADIUS_ATTR_PKM_AUTH_KEY,                     "PKM-Auth-Key"},
   {RADIUS_ATTR_DS_LITE_TUNNEL_NAME,              "DS-Lite-Tunnel-Name"},
   {RADIUS_ATTR_MOBILE_NODE_IDENTIFIER,           "Mobile-Node-Identifier"},
   {RADIUS_ATTR_SERVICE_SELECTION,                "Service-Selection"},
   {RADIUS_ATTR_PMIP6_HOME_LMA_IPV6_ADDR,         "PMIP6-Home-LMA-IPv6-Address"},
   {RADIUS_ATTR_PMIP6_VISITED_LMA_IPV6_ADDR,      "PMIP6-Visited-LMA-IPv6-Address"},
   {RADIUS_ATTR_PMIP6_HOME_LMA_IPV4_ADDR,         "PMIP6-Home-LMA-IPv4-Address"},
   {RADIUS_ATTR_PMIP6_VISITED_LMA_IPV4_ADDR,      "PMIP6-Visited-LMA-IPv4-Address"},
   {RADIUS_ATTR_PMIP6_HOME_HN_PREFIX,             "PMIP6-Home-HN-Prefix"},
   {RADIUS_ATTR_PMIP6_VISITED_HN_PREFIX,          "PMIP6-Visited-HN-Prefix"},
   {RADIUS_ATTR_PMIP6_HOME_INTERFACE_ID,          "PMIP6-Home-Interface-ID"},
   {RADIUS_ATTR_PMIP6_VISITED_INTERFACE_ID,       "PMIP6-Visited-Interface-ID"},
   {RADIUS_ATTR_PMIP6_HOME_IPV4_HOA,              "PMIP6-Home-IPv4-HoA"},
   {RADIUS_ATTR_PMIP6_VISITED_IPV4_HOA,           "PMIP6-Visited-IPv4-HoA"},
   {RADIUS_ATTR_PMIP6_HOME_DHCP4_SERVER_ADDR,     "PMIP6-Home-DHCP4-Server-Address"},
   {RADIUS_ATTR_PMIP6_VISITED_DHCP4_SERVER_ADDR,  "PMIP6-Visited-DHCP4-Server-Address"},
   {RADIUS_ATTR_PMIP6_HOME_DHCP6_SERVER_ADDR,     "PMIP6-Home-DHCP6-Server-Address"},
   {RADIUS_ATTR_PMIP6_VISITED_DHCP6_SERVER_ADDR,  "PMIP6-Visited-DHCP6-Server-Address"},
   {RADIUS_ATTR_PMIP6_HOME_IPV4_GATEWAY,          "PMIP6-Home-IPv4-Gateway"},
   {RADIUS_ATTR_PMIP6_VISITED_IPV4_GATEWAY,       "PMIP6-Visited-IPv4-Gateway"},
   {RADIUS_ATTR_EAP_LOWER_LAYER,                  "EAP-Lower-Layer"},
   {RADIUS_ATTR_GSS_ACCEPTOR_SERVICE_NAME,        "GSS-Acceptor-Service-Name"},
   {RADIUS_ATTR_GSS_ACCEPTOR_HOST_NAME,           "GSS-Acceptor-Host-Name"},
   {RADIUS_ATTR_GSS_ACCEPTOR_SERVICE_SPECIFICS,   "GSS-Acceptor-Service-Specifics"},
   {RADIUS_ATTR_GSS_ACCEPTOR_REALM_NAME,          "GSS-Acceptor-Realm-Name"},
   {RADIUS_ATTR_FRAMED_IPV6_ADDR,                 "Framed-IPv6-Address"},
   {RADIUS_ATTR_DNS_SERVER_IPV6_ADDR,             "DNS-Server-IPv6-Address"},
   {RADIUS_ATTR_ROUTE_IPV6_INFORMATION,           "Route-IPv6-Information"},
   {RADIUS_ATTR_DELEGATED_IPV6_PREFIX_POOL,       "Delegated-IPv6-Prefix-Pool"},
   {RADIUS_ATTR_STATEFUL_IPV6_ADDR_POOL,          "Stateful-IPv6-Address-Pool"},
   {RADIUS_ATTR_IPV6_6RD_CONFIGURATION,           "IPv6-6rd-Configuration"},
   {RADIUS_ATTR_ALLOWED_CALLED_STATION_ID,        "Allowed-Called-Station-Id"},
   {RADIUS_ATTR_EAP_PEER_ID,                      "EAP-Peer-Id"},
   {RADIUS_ATTR_EAP_SERVER_ID,                    "EAP-Server-Id"},
   {RADIUS_ATTR_MOBILITY_DOMAIN_ID,               "Mobility-Domain-Id"},
   {RADIUS_ATTR_PREAUTH_TIMEOUT,                  "Preauth-Timeout"},
   {RADIUS_ATTR_NETWORK_ID_NAME,                  "Network-Id-Name"},
   {RADIUS_ATTR_EAPOL_ANNOUNCEMENT,               "EAPoL-Announcement"},
   {RADIUS_ATTR_WLAN_HESSID,                      "WLAN-HESSID"},
   {RADIUS_ATTR_WLAN_VENUE_INFO,                  "WLAN-Venue-Info"},
   {RADIUS_ATTR_WLAN_VENUE_LANGUAGE,              "WLAN-Venue-Language"},
   {RADIUS_ATTR_WLAN_VENUE_NAME,                  "WLAN-Venue-Name"},
   {RADIUS_ATTR_WLAN_REASON_CODE,                 "WLAN-Reason-Code"},
   {RADIUS_ATTR_WLAN_PAIRWISE_CIPHER,             "WLAN-Pairwise-Cipher"},
   {RADIUS_ATTR_WLAN_GROUP_CIPHER,                "WLAN-Group-Cipher"},
   {RADIUS_ATTR_WLAN_AKM_SUITE,                   "WLAN-AKM-Suite"},
   {RADIUS_ATTR_WLAN_GROUP_MGMT_CIPHER,           "WLAN-Group-Mgmt-Cipher"},
   {RADIUS_ATTR_WLAN_RF_BAND,                     "WLAN-RF-Band"},
   {RADIUS_ATTR_EXTENDED_ATTR_1,                  "Extended-Attribute-1"},
   {RADIUS_ATTR_EXTENDED_ATTR_2,                  "Extended-Attribute-2"},
   {RADIUS_ATTR_EXTENDED_ATTR_3,                  "Extended-Attribute-3"},
   {RADIUS_ATTR_EXTENDED_ATTR_4,                  "Extended-Attribute-4"},
   {RADIUS_ATTR_EXTENDED_ATTR_5,                  "Extended-Attribute-5"},
   {RADIUS_ATTR_EXTENDED_ATTR_6,                  "Extended-Attribute-6"}
};


/**
 * @brief Dump RADIUS packet for debugging purpose
 * @param[in] packet Pointer to the RADIUS packet
 * @param[in] length Length of the RADIUS packet, in bytes
 **/

void radiusDumpPacket(const RadiusPacket *packet, size_t length)
{
   size_t i;
   const char_t *codeName;
   const RadiusAttribute *attribute;

   //Check the length of the RADIUS packet
   if(length >= sizeof(RadiusPacket))
   {
      //Convert the Code field to string representation
      codeName = radiusGetParamName(packet->code, radiusCodeList,
         arraysize(radiusCodeList));

      //Dump RADIUS packet contents
      TRACE_DEBUG("  Code = %" PRIu8 " (%s)\r\n", packet->code, codeName);
      TRACE_DEBUG("  Identifier = %" PRIu8 "\r\n", packet->identifier);
      TRACE_DEBUG("  Length = %" PRIu16 "\r\n", ntohs(packet->length));
      TRACE_DEBUG("  Authenticator\r\n");
      TRACE_DEBUG_ARRAY("    ", packet->authenticator, 16);

      //Calculate the length of the RADIUS attributes
      length -= sizeof(RadiusPacket);

      //Loop through the attributes
      for(i = 0; i < length; i += attribute->length)
      {
         //Point to the attribute
         attribute = (RadiusAttribute *) (packet->attributes + i);

         //Malformed attribute?
         if(attribute->length < sizeof(RadiusAttribute) ||
            attribute->length > (length - i))
         {
            break;
         }

         //Dump RADIUS attribute
         radiusDumpAttribute(attribute);
      }
   }
}


/**
 * @brief Dump RADIUS attribute
 * @param[in] attribute Pointer to the RADIUS attribute
 **/

void radiusDumpAttribute(const RadiusAttribute *attribute)
{
   size_t length;
   const char_t *typeName;

   //Check the length of the RADIUS attribute
   if(attribute->length >= sizeof(RadiusAttribute))
   {
      //Retrieve the length of the Value field
      length = attribute->length - sizeof(RadiusAttribute);

      //Convert the Type field to string representation
      typeName = radiusGetParamName(attribute->type, radiusAttrTypeList,
         arraysize(radiusAttrTypeList));

      //Display the name of the current RADIUS attribute
      if(osStrcmp(typeName, "Unknown") != 0)
      {
         TRACE_DEBUG("  %s Attribute (%" PRIuSIZE " bytes)\r\n", typeName,
            length);
      }
      else
      {
         TRACE_DEBUG("  Attribute %" PRIu8 " (%" PRIuSIZE " bytes)\r\n",
            attribute->type, length);
      }

      //Check attribute type
      switch(attribute->type)
      {
      //32-bit unsigned integer?
      case RADIUS_ATTR_NAS_PORT:
      case RADIUS_ATTR_SERVICE_TYPE:
      case RADIUS_ATTR_FRAMED_MTU:
      case RADIUS_ATTR_NAS_PORT_TYPE:
         radiusDumpInt32(attribute->value, length);
         break;

      //Character strings?
      case RADIUS_ATTR_USER_NAME:
      case RADIUS_ATTR_FILTER_ID:
      case RADIUS_ATTR_REPLY_MESSAGE:
      case RADIUS_ATTR_CALLBACK_NUMBER:
      case RADIUS_ATTR_CALLBACK_ID:
      case RADIUS_ATTR_FRAMED_ROUTE:
      case RADIUS_ATTR_CALLED_STATION_ID:
      case RADIUS_ATTR_CALLING_STATION_ID:
      case RADIUS_ATTR_NAS_IDENTIFIER:
      case RADIUS_ATTR_LOGIN_LAT_SERVICE:
      case RADIUS_ATTR_LOGIN_LAT_NODE:
      case RADIUS_ATTR_FRAMED_APPLETALK_ZONE:
      case RADIUS_ATTR_ACCT_SESSION_ID:
      case RADIUS_ATTR_ACCT_MULTI_SESSION_ID:
      case RADIUS_ATTR_EGRESS_VLAN_NAME:
      case RADIUS_ATTR_LOGIN_LAT_PORT:
      case RADIUS_ATTR_TUNNEL_CLIENT_ENDPOINT:
      case RADIUS_ATTR_TUNNEL_SERVER_ENDPOINT:
      case RADIUS_ATTR_ACCT_TUNNEL_CONNECTION:
      case RADIUS_ATTR_ARAP_SECURITY_DATA:
      case RADIUS_ATTR_CONNECT_INFO:
      case RADIUS_ATTR_CONFIGURATION_TOKEN:
      case RADIUS_ATTR_TUNNEL_PRIVATE_GROUP_ID:
      case RADIUS_ATTR_TUNNEL_ASSIGNMENT_ID:
      case RADIUS_ATTR_NAS_PORT_ID:
      case RADIUS_ATTR_FRAMED_POOL:
      case RADIUS_ATTR_TUNNEL_CLIENT_AUTH_ID:
      case RADIUS_ATTR_TUNNEL_SERVER_AUTH_ID:
      case RADIUS_ATTR_NAS_FILTER_RULE:
      case RADIUS_ATTR_FRAMED_IPV6_ROUTE:
      case RADIUS_ATTR_FRAMED_IPV6_POOL:
      case RADIUS_ATTR_DIGEST_RESPONSE:
      case RADIUS_ATTR_DIGEST_REALM:
      case RADIUS_ATTR_DIGEST_NONCE:
      case RADIUS_ATTR_DIGEST_RESPONSE_AUTH:
      case RADIUS_ATTR_DIGEST_NEXTNONCE:
      case RADIUS_ATTR_DIGEST_METHOD:
      case RADIUS_ATTR_DIGEST_URI:
      case RADIUS_ATTR_DIGEST_QOP:
      case RADIUS_ATTR_DIGEST_ALGORITHM:
      case RADIUS_ATTR_DIGEST_ENTITY_BODY_HASH:
      case RADIUS_ATTR_DIGEST_CNONCE:
      case RADIUS_ATTR_DIGEST_NONCE_COUNT:
      case RADIUS_ATTR_DIGEST_USERNAME:
      case RADIUS_ATTR_DIGEST_OPAQUE:
      case RADIUS_ATTR_DIGEST_AUTH_PARAM:
      case RADIUS_ATTR_DIGEST_AKA_AUTS:
      case RADIUS_ATTR_DIGEST_DOMAIN:
      case RADIUS_ATTR_DIGEST_STALE:
      case RADIUS_ATTR_DIGEST_HA1:
      case RADIUS_ATTR_SIP_AOR:
      case RADIUS_ATTR_OPERATOR_NAME:
      case RADIUS_ATTR_MANAGEMENT_POLICY_ID:
      case RADIUS_ATTR_PKM_SAID:
      case RADIUS_ATTR_SERVICE_SELECTION:
      case RADIUS_ATTR_GSS_ACCEPTOR_SERVICE_NAME:
      case RADIUS_ATTR_GSS_ACCEPTOR_HOST_NAME:
      case RADIUS_ATTR_GSS_ACCEPTOR_SERVICE_SPECIFICS:
      case RADIUS_ATTR_GSS_ACCEPTOR_REALM_NAME:
      case RADIUS_ATTR_DELEGATED_IPV6_PREFIX_POOL:
      case RADIUS_ATTR_STATEFUL_IPV6_ADDR_POOL:
      case RADIUS_ATTR_ALLOWED_CALLED_STATION_ID:
      case RADIUS_ATTR_WLAN_HESSID:
      case RADIUS_ATTR_WLAN_VENUE_NAME:
         radiusDumpString(attribute->value, length);
         break;

      //IPv4 address?
      case RADIUS_ATTR_NAS_IP_ADDR:
      case RADIUS_ATTR_FRAMED_IP_ADDR:
      case RADIUS_ATTR_FRAMED_IP_NETMASK:
      case RADIUS_ATTR_LOGIN_IP_HOST:
      case RADIUS_ATTR_FRAMED_IPX_NETWORK:
      case RADIUS_ATTR_PMIP6_HOME_LMA_IPV4_ADDR:
      case RADIUS_ATTR_PMIP6_VISITED_LMA_IPV4_ADDR:
      case RADIUS_ATTR_PMIP6_HOME_DHCP4_SERVER_ADDR:
      case RADIUS_ATTR_PMIP6_VISITED_DHCP4_SERVER_ADDR:
      case RADIUS_ATTR_PMIP6_HOME_IPV4_GATEWAY:
      case RADIUS_ATTR_PMIP6_VISITED_IPV4_GATEWAY:
         radiusDumpIpv4Addr(attribute->value, length);
         break;

      //IPv6 address?
      case RADIUS_ATTR_NAS_IPV6_ADDR:
      case RADIUS_ATTR_LOGIN_IPV6_HOST:
      case RADIUS_ATTR_PMIP6_HOME_LMA_IPV6_ADDR:
      case RADIUS_ATTR_PMIP6_VISITED_LMA_IPV6_ADDR:
      case RADIUS_ATTR_PMIP6_HOME_DHCP6_SERVER_ADDR:
      case RADIUS_ATTR_PMIP6_VISITED_DHCP6_SERVER_ADDR:
      case RADIUS_ATTR_FRAMED_IPV6_ADDR:
      case RADIUS_ATTR_DNS_SERVER_IPV6_ADDR:
         radiusDumpIpv6Addr(attribute->value, length);
         break;

      //Unknown format?
      default:
         radiusDumpRawData(attribute->value, length);
         break;
      }
   }
}


/**
 * @brief Dump an attribute containing a 32-bit integer
 * @param[in] data Attribute value
 * @param[in] length Attribute length
 **/

void radiusDumpInt32(const uint8_t *data, size_t length)
{
   uint32_t value;

   //Check the length of the attribute
   if(length == sizeof(uint32_t))
   {
      //Retrieve 32-bit value
      value = LOAD32BE(data);
      //Dump option contents
      TRACE_DEBUG("    %" PRIu32 "\r\n", value);
   }
}


/**
 * @brief Dump an attribute containing a string
 * @param[in] data Attribute value
 * @param[in] length Attribute length
 **/

void radiusDumpString(const uint8_t *data, size_t length)
{
   size_t i;

   //Display prefix
   TRACE_DEBUG("    \"");

   //Dump attribute value
   for(i = 0; i < length; i++)
   {
      TRACE_DEBUG("%c", data[i]);
   }

   //Display suffix
   TRACE_DEBUG("\"\r\n");
}


/**
 * @brief Dump an attribute containing an IPv4 address
 * @param[in] data Attribute value
 * @param[in] length Attribute length
 **/

void radiusDumpIpv4Addr(const uint8_t *data, size_t length)
{
#if (IPV4_SUPPORT == ENABLED)
   Ipv4Addr ipAddr;

   //Check the length of the attribute
   if(length == sizeof(Ipv4Addr))
   {
      //Retrieve IPv4 address
      ipv4CopyAddr(&ipAddr, data);
      //Dump option contents
      TRACE_DEBUG("    %s\r\n", ipv4AddrToString(ipAddr, NULL));
   }
#endif
}


/**
 * @brief Dump an attribute containing an IPv6 address
 * @param[in] data Attribute value
 * @param[in] length Attribute length
 **/

void radiusDumpIpv6Addr(const uint8_t *data, size_t length)
{
#if (IPV6_SUPPORT == ENABLED)
   Ipv6Addr ipAddr;

   //Check the length of the attribute
   if(length == sizeof(Ipv6Addr))
   {
      //Retrieve IPv6 address
      ipv6CopyAddr(&ipAddr, data);
      //Dump option contents
      TRACE_DEBUG("    %s\r\n", ipv6AddrToString(&ipAddr, NULL));
   }
#endif
}


/**
 * @brief Dump an attribute containing raw data
 * @param[in] data Attribute value
 * @param[in] length Attribute length
 **/

void radiusDumpRawData(const uint8_t *data, size_t length)
{
   //Dump attribute value
   if(length <= 32)
   {
      TRACE_DEBUG_ARRAY("    ", data, length);
   }
   else
   {
      TRACE_VERBOSE_ARRAY("    ", data, length);
   }
}


/**
 * @brief Convert a parameter to string representation
 * @param[in] value Parameter value
 * @param[in] paramList List of acceptable parameters
 * @param[in] paramListLen Number of entries in the list
 * @return NULL-terminated string describing the parameter
 **/

const char_t *radiusGetParamName(uint_t value, const RadiusParamName *paramList,
   size_t paramListLen)
{
   uint_t i;

   //Default name for unknown values
   static const char_t defaultName[] = "Unknown";

   //Loop through the list of acceptable parameters
   for(i = 0; i < paramListLen; i++)
   {
      if(paramList[i].value == value)
      {
         return paramList[i].name;
      }
   }

   //Unknown value
   return defaultName;
}

#endif
