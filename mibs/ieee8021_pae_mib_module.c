/**
 * @file ieee8021_pae_mib_module.c
 * @brief Port Access Control MIB module
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
#define TRACE_LEVEL SNMP_TRACE_LEVEL

//Dependencies
#include "core/net.h"
#include "mibs/mib_common.h"
#include "mibs/ieee8021_pae_mib_module.h"
#include "mibs/ieee8021_pae_mib_impl.h"
#include "mibs/ieee8021_pae_mib_impl_sys.h"
#include "mibs/ieee8021_pae_mib_impl_auth.h"
#include "core/crypto.h"
#include "encoding/asn1.h"
#include "encoding/oid.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (IEEE8021_PAE_MIB_SUPPORT == ENABLED)


/**
 * @brief Port Access Control MIB base
 **/

Ieee8021PaeMibBase ieee8021PaeMibBase;


/**
 * @brief Port Access Control MIB objects
 **/

const MibObject ieee8021PaeMibObjects[] =
{
   //dot1xPaeSystemAuthControl object (1.0.8802.1.1.1.1.1.1)
   {
      "dot1xPaeSystemAuthControl",
      {40, 196, 98, 1, 1, 1, 1, 1, 1},
      9,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_INTEGER,
      MIB_ACCESS_READ_WRITE,
      NULL,
      NULL,
      sizeof(int32_t),
      ieee8021PaeMibSetDot1xPaeSystemAuthControl,
      ieee8021PaeMibGetDot1xPaeSystemAuthControl,
      NULL
   },
   //dot1xPaePortProtocolVersion object (1.0.8802.1.1.1.1.1.2.1.2)
   {
      "dot1xPaePortProtocolVersion",
      {40, 196, 98, 1, 1, 1, 1, 1, 2, 1, 2},
      11,
      ASN1_CLASS_APPLICATION,
      MIB_TYPE_UNSIGNED32,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      sizeof(uint32_t),
      NULL,
      ieee8021PaeMibGetDot1xPaePortEntry,
      ieee8021PaeMibGetNextDot1xPaePortEntry
   },
   //dot1xPaePortCapabilities object (1.0.8802.1.1.1.1.1.2.1.3)
   {
      "dot1xPaePortCapabilities",
      {40, 196, 98, 1, 1, 1, 1, 1, 2, 1, 3},
      11,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_OCTET_STRING,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      0,
      NULL,
      ieee8021PaeMibGetDot1xPaePortEntry,
      ieee8021PaeMibGetNextDot1xPaePortEntry
   },
   //dot1xPaePortInitialize object (1.0.8802.1.1.1.1.1.2.1.4)
   {
      "dot1xPaePortInitialize",
      {40, 196, 98, 1, 1, 1, 1, 1, 2, 1, 4},
      11,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_INTEGER,
      MIB_ACCESS_READ_WRITE,
      NULL,
      NULL,
      sizeof(int32_t),
      ieee8021PaeMibSetDot1xPaePortEntry,
      ieee8021PaeMibGetDot1xPaePortEntry,
      ieee8021PaeMibGetNextDot1xPaePortEntry
   },
   //dot1xPaePortReauthenticate object (1.0.8802.1.1.1.1.1.2.1.5)
   {
      "dot1xPaePortReauthenticate",
      {40, 196, 98, 1, 1, 1, 1, 1, 2, 1, 5},
      11,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_INTEGER,
      MIB_ACCESS_READ_WRITE,
      NULL,
      NULL,
      sizeof(int32_t),
      ieee8021PaeMibSetDot1xPaePortEntry,
      ieee8021PaeMibGetDot1xPaePortEntry,
      ieee8021PaeMibGetNextDot1xPaePortEntry
   },
#if (AUTHENTICATOR_SUPPORT == ENABLED)
   //dot1xAuthPaeState object (1.0.8802.1.1.1.1.2.1.1.1)
   {
      "dot1xAuthPaeState",
      {40, 196, 98, 1, 1, 1, 1, 2, 1, 1, 1},
      11,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_INTEGER,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      sizeof(int32_t),
      NULL,
      ieee8021PaeMibGetDot1xAuthConfigEntry,
      ieee8021PaeMibGetNextDot1xAuthConfigEntry
   },
   //dot1xAuthBackendAuthState object (1.0.8802.1.1.1.1.2.1.1.2)
   {
      "dot1xAuthBackendAuthState",
      {40, 196, 98, 1, 1, 1, 1, 2, 1, 1, 2},
      11,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_INTEGER,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      sizeof(int32_t),
      NULL,
      ieee8021PaeMibGetDot1xAuthConfigEntry,
      ieee8021PaeMibGetNextDot1xAuthConfigEntry
   },
   //dot1xAuthAdminControlledDirections object (1.0.8802.1.1.1.1.2.1.1.3)
   {
      "dot1xAuthAdminControlledDirections",
      {40, 196, 98, 1, 1, 1, 1, 2, 1, 1, 3},
      11,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_INTEGER,
      MIB_ACCESS_READ_WRITE,
      NULL,
      NULL,
      sizeof(int32_t),
      ieee8021PaeMibSetDot1xAuthConfigEntry,
      ieee8021PaeMibGetDot1xAuthConfigEntry,
      ieee8021PaeMibGetNextDot1xAuthConfigEntry
   },
   //dot1xAuthOperControlledDirections object (1.0.8802.1.1.1.1.2.1.1.4)
   {
      "dot1xAuthOperControlledDirections",
      {40, 196, 98, 1, 1, 1, 1, 2, 1, 1, 4},
      11,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_INTEGER,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      sizeof(int32_t),
      NULL,
      ieee8021PaeMibGetDot1xAuthConfigEntry,
      ieee8021PaeMibGetNextDot1xAuthConfigEntry
   },
   //dot1xAuthAuthControlledPortStatus object (1.0.8802.1.1.1.1.2.1.1.5)
   {
      "dot1xAuthAuthControlledPortStatus",
      {40, 196, 98, 1, 1, 1, 1, 2, 1, 1, 5},
      11,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_INTEGER,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      sizeof(int32_t),
      NULL,
      ieee8021PaeMibGetDot1xAuthConfigEntry,
      ieee8021PaeMibGetNextDot1xAuthConfigEntry
   },
   //dot1xAuthAuthControlledPortControl object (1.0.8802.1.1.1.1.2.1.1.6)
   {
      "dot1xAuthAuthControlledPortControl",
      {40, 196, 98, 1, 1, 1, 1, 2, 1, 1, 6},
      11,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_INTEGER,
      MIB_ACCESS_READ_WRITE,
      NULL,
      NULL,
      sizeof(int32_t),
      ieee8021PaeMibSetDot1xAuthConfigEntry,
      ieee8021PaeMibGetDot1xAuthConfigEntry,
      ieee8021PaeMibGetNextDot1xAuthConfigEntry
   },
   //dot1xAuthQuietPeriod object (1.0.8802.1.1.1.1.2.1.1.7)
   {
      "dot1xAuthQuietPeriod",
      {40, 196, 98, 1, 1, 1, 1, 2, 1, 1, 7},
      11,
      ASN1_CLASS_APPLICATION,
      MIB_TYPE_UNSIGNED32,
      MIB_ACCESS_READ_WRITE,
      NULL,
      NULL,
      sizeof(uint32_t),
      ieee8021PaeMibSetDot1xAuthConfigEntry,
      ieee8021PaeMibGetDot1xAuthConfigEntry,
      ieee8021PaeMibGetNextDot1xAuthConfigEntry
   },
   //dot1xAuthServerTimeout object (1.0.8802.1.1.1.1.2.1.1.10)
   {
      "dot1xAuthServerTimeout",
      {40, 196, 98, 1, 1, 1, 1, 2, 1, 1, 10},
      11,
      ASN1_CLASS_APPLICATION,
      MIB_TYPE_UNSIGNED32,
      MIB_ACCESS_READ_WRITE,
      NULL,
      NULL,
      sizeof(uint32_t),
      ieee8021PaeMibSetDot1xAuthConfigEntry,
      ieee8021PaeMibGetDot1xAuthConfigEntry,
      ieee8021PaeMibGetNextDot1xAuthConfigEntry
   },
   //dot1xAuthReAuthPeriod object (1.0.8802.1.1.1.1.2.1.1.12)
   {
      "dot1xAuthReAuthPeriod",
      {40, 196, 98, 1, 1, 1, 1, 2, 1, 1, 12},
      11,
      ASN1_CLASS_APPLICATION,
      MIB_TYPE_UNSIGNED32,
      MIB_ACCESS_READ_WRITE,
      NULL,
      NULL,
      sizeof(uint32_t),
      ieee8021PaeMibSetDot1xAuthConfigEntry,
      ieee8021PaeMibGetDot1xAuthConfigEntry,
      ieee8021PaeMibGetNextDot1xAuthConfigEntry
   },
   //dot1xAuthReAuthEnabled object (1.0.8802.1.1.1.1.2.1.1.13)
   {
      "dot1xAuthReAuthEnabled",
      {40, 196, 98, 1, 1, 1, 1, 2, 1, 1, 13},
      11,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_INTEGER,
      MIB_ACCESS_READ_WRITE,
      NULL,
      NULL,
      sizeof(int32_t),
      ieee8021PaeMibSetDot1xAuthConfigEntry,
      ieee8021PaeMibGetDot1xAuthConfigEntry,
      ieee8021PaeMibGetNextDot1xAuthConfigEntry
   },
   //dot1xAuthKeyTxEnabled object (1.0.8802.1.1.1.1.2.1.1.14)
   {
      "dot1xAuthKeyTxEnabled",
      {40, 196, 98, 1, 1, 1, 1, 2, 1, 1, 14},
      11,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_INTEGER,
      MIB_ACCESS_READ_WRITE,
      NULL,
      NULL,
      sizeof(int32_t),
      ieee8021PaeMibSetDot1xAuthConfigEntry,
      ieee8021PaeMibGetDot1xAuthConfigEntry,
      ieee8021PaeMibGetNextDot1xAuthConfigEntry
   },
   //dot1xAuthEapolFramesRx object (1.0.8802.1.1.1.1.2.2.1.1)
   {
      "dot1xAuthEapolFramesRx",
      {40, 196, 98, 1, 1, 1, 1, 2, 2, 1, 1},
      11,
      ASN1_CLASS_APPLICATION,
      MIB_TYPE_COUNTER32,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      sizeof(uint32_t),
      NULL,
      ieee8021PaeMibGetDot1xAuthStatsEntry,
      ieee8021PaeMibGetNextDot1xAuthStatsEntry
   },
   //dot1xAuthEapolFramesTx object (1.0.8802.1.1.1.1.2.2.1.2)
   {
      "dot1xAuthEapolFramesTx",
      {40, 196, 98, 1, 1, 1, 1, 2, 2, 1, 2},
      11,
      ASN1_CLASS_APPLICATION,
      MIB_TYPE_COUNTER32,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      sizeof(uint32_t),
      NULL,
      ieee8021PaeMibGetDot1xAuthStatsEntry,
      ieee8021PaeMibGetNextDot1xAuthStatsEntry
   },
   //dot1xAuthEapolStartFramesRx object (1.0.8802.1.1.1.1.2.2.1.3)
   {
      "dot1xAuthEapolStartFramesRx",
      {40, 196, 98, 1, 1, 1, 1, 2, 2, 1, 3},
      11,
      ASN1_CLASS_APPLICATION,
      MIB_TYPE_COUNTER32,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      sizeof(uint32_t),
      NULL,
      ieee8021PaeMibGetDot1xAuthStatsEntry,
      ieee8021PaeMibGetNextDot1xAuthStatsEntry
   },
   //dot1xAuthEapolLogoffFramesRx object (1.0.8802.1.1.1.1.2.2.1.4)
   {
      "dot1xAuthEapolLogoffFramesRx",
      {40, 196, 98, 1, 1, 1, 1, 2, 2, 1, 4},
      11,
      ASN1_CLASS_APPLICATION,
      MIB_TYPE_COUNTER32,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      sizeof(uint32_t),
      NULL,
      ieee8021PaeMibGetDot1xAuthStatsEntry,
      ieee8021PaeMibGetNextDot1xAuthStatsEntry
   },
   //dot1xAuthEapolRespIdFramesRx object (1.0.8802.1.1.1.1.2.2.1.5)
   {
      "dot1xAuthEapolRespIdFramesRx",
      {40, 196, 98, 1, 1, 1, 1, 2, 2, 1, 5},
      11,
      ASN1_CLASS_APPLICATION,
      MIB_TYPE_COUNTER32,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      sizeof(uint32_t),
      NULL,
      ieee8021PaeMibGetDot1xAuthStatsEntry,
      ieee8021PaeMibGetNextDot1xAuthStatsEntry
   },
   //dot1xAuthEapolRespFramesRx object (1.0.8802.1.1.1.1.2.2.1.6)
   {
      "dot1xAuthEapolRespFramesRx",
      {40, 196, 98, 1, 1, 1, 1, 2, 2, 1, 6},
      11,
      ASN1_CLASS_APPLICATION,
      MIB_TYPE_COUNTER32,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      sizeof(uint32_t),
      NULL,
      ieee8021PaeMibGetDot1xAuthStatsEntry,
      ieee8021PaeMibGetNextDot1xAuthStatsEntry
   },
   //dot1xAuthEapolReqIdFramesTx object (1.0.8802.1.1.1.1.2.2.1.7)
   {
      "dot1xAuthEapolReqIdFramesTx",
      {40, 196, 98, 1, 1, 1, 1, 2, 2, 1, 7},
      11,
      ASN1_CLASS_APPLICATION,
      MIB_TYPE_COUNTER32,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      sizeof(uint32_t),
      NULL,
      ieee8021PaeMibGetDot1xAuthStatsEntry,
      ieee8021PaeMibGetNextDot1xAuthStatsEntry
   },
   //dot1xAuthEapolReqFramesTx object (1.0.8802.1.1.1.1.2.2.1.8)
   {
      "dot1xAuthEapolReqFramesTx",
      {40, 196, 98, 1, 1, 1, 1, 2, 2, 1, 8},
      11,
      ASN1_CLASS_APPLICATION,
      MIB_TYPE_COUNTER32,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      sizeof(uint32_t),
      NULL,
      ieee8021PaeMibGetDot1xAuthStatsEntry,
      ieee8021PaeMibGetNextDot1xAuthStatsEntry
   },
   //dot1xAuthInvalidEapolFramesRx object (1.0.8802.1.1.1.1.2.2.1.9)
   {
      "dot1xAuthInvalidEapolFramesRx",
      {40, 196, 98, 1, 1, 1, 1, 2, 2, 1, 9},
      11,
      ASN1_CLASS_APPLICATION,
      MIB_TYPE_COUNTER32,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      sizeof(uint32_t),
      NULL,
      ieee8021PaeMibGetDot1xAuthStatsEntry,
      ieee8021PaeMibGetNextDot1xAuthStatsEntry
   },
   //dot1xAuthEapLengthErrorFramesRx object (1.0.8802.1.1.1.1.2.2.1.10)
   {
      "dot1xAuthEapLengthErrorFramesRx",
      {40, 196, 98, 1, 1, 1, 1, 2, 2, 1, 10},
      11,
      ASN1_CLASS_APPLICATION,
      MIB_TYPE_COUNTER32,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      sizeof(uint32_t),
      NULL,
      ieee8021PaeMibGetDot1xAuthStatsEntry,
      ieee8021PaeMibGetNextDot1xAuthStatsEntry
   },
   //dot1xAuthLastEapolFrameVersion object (1.0.8802.1.1.1.1.2.2.1.11)
   {
      "dot1xAuthLastEapolFrameVersion",
      {40, 196, 98, 1, 1, 1, 1, 2, 2, 1, 11},
      11,
      ASN1_CLASS_APPLICATION,
      MIB_TYPE_UNSIGNED32,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      sizeof(uint32_t),
      NULL,
      ieee8021PaeMibGetDot1xAuthStatsEntry,
      ieee8021PaeMibGetNextDot1xAuthStatsEntry
   },
   //dot1xAuthLastEapolFrameSource object (1.0.8802.1.1.1.1.2.2.1.12)
   {
      "dot1xAuthLastEapolFrameSource",
      {40, 196, 98, 1, 1, 1, 1, 2, 2, 1, 12},
      11,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_OCTET_STRING,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      0,
      NULL,
      ieee8021PaeMibGetDot1xAuthStatsEntry,
      ieee8021PaeMibGetNextDot1xAuthStatsEntry
   },
   //dot1xAuthSessionOctetsRx object (1.0.8802.1.1.1.1.2.4.1.1)
   {
      "dot1xAuthSessionOctetsRx",
      {40, 196, 98, 1, 1, 1, 1, 2, 4, 1, 1},
      11,
      ASN1_CLASS_APPLICATION,
      MIB_TYPE_COUNTER64,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      sizeof(uint64_t),
      NULL,
      ieee8021PaeMibGetDot1xAuthSessionStatsEntry,
      ieee8021PaeMibGetNextDot1xAuthSessionStatsEntry
   },
   //dot1xAuthSessionOctetsTx object (1.0.8802.1.1.1.1.2.4.1.2)
   {
      "dot1xAuthSessionOctetsTx",
      {40, 196, 98, 1, 1, 1, 1, 2, 4, 1, 2},
      11,
      ASN1_CLASS_APPLICATION,
      MIB_TYPE_COUNTER64,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      sizeof(uint64_t),
      NULL,
      ieee8021PaeMibGetDot1xAuthSessionStatsEntry,
      ieee8021PaeMibGetNextDot1xAuthSessionStatsEntry
   },
   //dot1xAuthSessionFramesRx object (1.0.8802.1.1.1.1.2.4.1.3)
   {
      "dot1xAuthSessionFramesRx",
      {40, 196, 98, 1, 1, 1, 1, 2, 4, 1, 3},
      11,
      ASN1_CLASS_APPLICATION,
      MIB_TYPE_COUNTER32,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      sizeof(uint32_t),
      NULL,
      ieee8021PaeMibGetDot1xAuthSessionStatsEntry,
      ieee8021PaeMibGetNextDot1xAuthSessionStatsEntry
   },
   //dot1xAuthSessionFramesTx object (1.0.8802.1.1.1.1.2.4.1.4)
   {
      "dot1xAuthSessionFramesTx",
      {40, 196, 98, 1, 1, 1, 1, 2, 4, 1, 4},
      11,
      ASN1_CLASS_APPLICATION,
      MIB_TYPE_COUNTER32,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      sizeof(uint32_t),
      NULL,
      ieee8021PaeMibGetDot1xAuthSessionStatsEntry,
      ieee8021PaeMibGetNextDot1xAuthSessionStatsEntry
   },
   //dot1xAuthSessionId object (1.0.8802.1.1.1.1.2.4.1.5)
   {
      "dot1xAuthSessionId",
      {40, 196, 98, 1, 1, 1, 1, 2, 4, 1, 5},
      11,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_OCTET_STRING,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      0,
      NULL,
      ieee8021PaeMibGetDot1xAuthSessionStatsEntry,
      ieee8021PaeMibGetNextDot1xAuthSessionStatsEntry
   },
   //dot1xAuthSessionAuthenticMethod object (1.0.8802.1.1.1.1.2.4.1.6)
   {
      "dot1xAuthSessionAuthenticMethod",
      {40, 196, 98, 1, 1, 1, 1, 2, 4, 1, 6},
      11,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_INTEGER,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      sizeof(int32_t),
      NULL,
      ieee8021PaeMibGetDot1xAuthSessionStatsEntry,
      ieee8021PaeMibGetNextDot1xAuthSessionStatsEntry
   },
   //dot1xAuthSessionTime object (1.0.8802.1.1.1.1.2.4.1.7)
   {
      "dot1xAuthSessionTime",
      {40, 196, 98, 1, 1, 1, 1, 2, 4, 1, 7},
      11,
      ASN1_CLASS_APPLICATION,
      MIB_TYPE_TIME_TICKS,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      sizeof(uint32_t),
      NULL,
      ieee8021PaeMibGetDot1xAuthSessionStatsEntry,
      ieee8021PaeMibGetNextDot1xAuthSessionStatsEntry
   },
   //dot1xAuthSessionTerminateCause object (1.0.8802.1.1.1.1.2.4.1.8)
   {
      "dot1xAuthSessionTerminateCause",
      {40, 196, 98, 1, 1, 1, 1, 2, 4, 1, 8},
      11,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_INTEGER,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      sizeof(int32_t),
      NULL,
      ieee8021PaeMibGetDot1xAuthSessionStatsEntry,
      ieee8021PaeMibGetNextDot1xAuthSessionStatsEntry
   },
   //dot1xAuthSessionUserName object (1.0.8802.1.1.1.1.2.4.1.9)
   {
      "dot1xAuthSessionUserName",
      {40, 196, 98, 1, 1, 1, 1, 2, 4, 1, 9},
      11,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_OCTET_STRING,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      0,
      NULL,
      ieee8021PaeMibGetDot1xAuthSessionStatsEntry,
      ieee8021PaeMibGetNextDot1xAuthSessionStatsEntry
   },
#endif
#if 0
   //dot1xSuppPaeState object (1.0.8802.1.1.1.1.3.1.1.1)
   {
      "dot1xSuppPaeState",
      {40, 196, 98, 1, 1, 1, 1, 3, 1, 1, 1},
      11,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_INTEGER,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      sizeof(int32_t),
      NULL,
      ieee8021PaeMibGetDot1xSuppConfigEntry,
      ieee8021PaeMibGetNextDot1xSuppConfigEntry
   },
   //dot1xSuppHeldPeriod object (1.0.8802.1.1.1.1.3.1.1.2)
   {
      "dot1xSuppHeldPeriod",
      {40, 196, 98, 1, 1, 1, 1, 3, 1, 1, 2},
      11,
      ASN1_CLASS_APPLICATION,
      MIB_TYPE_UNSIGNED32,
      MIB_ACCESS_READ_WRITE,
      NULL,
      NULL,
      sizeof(uint32_t),
      ieee8021PaeMibSetDot1xSuppConfigEntry,
      ieee8021PaeMibGetDot1xSuppConfigEntry,
      ieee8021PaeMibGetNextDot1xSuppConfigEntry
   },
   //dot1xSuppAuthPeriod object (1.0.8802.1.1.1.1.3.1.1.3)
   {
      "dot1xSuppAuthPeriod",
      {40, 196, 98, 1, 1, 1, 1, 3, 1, 1, 3},
      11,
      ASN1_CLASS_APPLICATION,
      MIB_TYPE_UNSIGNED32,
      MIB_ACCESS_READ_WRITE,
      NULL,
      NULL,
      sizeof(uint32_t),
      ieee8021PaeMibSetDot1xSuppConfigEntry,
      ieee8021PaeMibGetDot1xSuppConfigEntry,
      ieee8021PaeMibGetNextDot1xSuppConfigEntry
   },
   //dot1xSuppStartPeriod object (1.0.8802.1.1.1.1.3.1.1.4)
   {
      "dot1xSuppStartPeriod",
      {40, 196, 98, 1, 1, 1, 1, 3, 1, 1, 4},
      11,
      ASN1_CLASS_APPLICATION,
      MIB_TYPE_UNSIGNED32,
      MIB_ACCESS_READ_WRITE,
      NULL,
      NULL,
      sizeof(uint32_t),
      ieee8021PaeMibSetDot1xSuppConfigEntry,
      ieee8021PaeMibGetDot1xSuppConfigEntry,
      ieee8021PaeMibGetNextDot1xSuppConfigEntry
   },
   //dot1xSuppMaxStart object (1.0.8802.1.1.1.1.3.1.1.5)
   {
      "dot1xSuppMaxStart",
      {40, 196, 98, 1, 1, 1, 1, 3, 1, 1, 5},
      11,
      ASN1_CLASS_APPLICATION,
      MIB_TYPE_UNSIGNED32,
      MIB_ACCESS_READ_WRITE,
      NULL,
      NULL,
      sizeof(uint32_t),
      ieee8021PaeMibSetDot1xSuppConfigEntry,
      ieee8021PaeMibGetDot1xSuppConfigEntry,
      ieee8021PaeMibGetNextDot1xSuppConfigEntry
   },
   //dot1xSuppControlledPortStatus object (1.0.8802.1.1.1.1.3.1.1.6)
   {
      "dot1xSuppControlledPortStatus",
      {40, 196, 98, 1, 1, 1, 1, 3, 1, 1, 6},
      11,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_INTEGER,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      sizeof(int32_t),
      NULL,
      ieee8021PaeMibGetDot1xSuppConfigEntry,
      ieee8021PaeMibGetNextDot1xSuppConfigEntry
   },
   //dot1xSuppAccessCtrlWithAuth object (1.0.8802.1.1.1.1.3.1.1.7)
   {
      "dot1xSuppAccessCtrlWithAuth",
      {40, 196, 98, 1, 1, 1, 1, 3, 1, 1, 7},
      11,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_INTEGER,
      MIB_ACCESS_READ_WRITE,
      NULL,
      NULL,
      sizeof(int32_t),
      ieee8021PaeMibSetDot1xSuppConfigEntry,
      ieee8021PaeMibGetDot1xSuppConfigEntry,
      ieee8021PaeMibGetNextDot1xSuppConfigEntry
   },
   //dot1xSuppBackendState object (1.0.8802.1.1.1.1.3.1.1.8)
   {
      "dot1xSuppBackendState",
      {40, 196, 98, 1, 1, 1, 1, 3, 1, 1, 8},
      11,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_INTEGER,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      sizeof(int32_t),
      NULL,
      ieee8021PaeMibGetDot1xSuppConfigEntry,
      ieee8021PaeMibGetNextDot1xSuppConfigEntry
   },
   //dot1xSuppEapolFramesRx object (1.0.8802.1.1.1.1.3.2.1.1)
   {
      "dot1xSuppEapolFramesRx",
      {40, 196, 98, 1, 1, 1, 1, 3, 2, 1, 1},
      11,
      ASN1_CLASS_APPLICATION,
      MIB_TYPE_COUNTER32,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      sizeof(uint32_t),
      NULL,
      ieee8021PaeMibGetDot1xSuppStatsEntry,
      ieee8021PaeMibGetNextDot1xSuppStatsEntry
   },
   //dot1xSuppEapolFramesTx object (1.0.8802.1.1.1.1.3.2.1.2)
   {
      "dot1xSuppEapolFramesTx",
      {40, 196, 98, 1, 1, 1, 1, 3, 2, 1, 2},
      11,
      ASN1_CLASS_APPLICATION,
      MIB_TYPE_COUNTER32,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      sizeof(uint32_t),
      NULL,
      ieee8021PaeMibGetDot1xSuppStatsEntry,
      ieee8021PaeMibGetNextDot1xSuppStatsEntry
   },
   //dot1xSuppEapolStartFramesTx object (1.0.8802.1.1.1.1.3.2.1.3)
   {
      "dot1xSuppEapolStartFramesTx",
      {40, 196, 98, 1, 1, 1, 1, 3, 2, 1, 3},
      11,
      ASN1_CLASS_APPLICATION,
      MIB_TYPE_COUNTER32,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      sizeof(uint32_t),
      NULL,
      ieee8021PaeMibGetDot1xSuppStatsEntry,
      ieee8021PaeMibGetNextDot1xSuppStatsEntry
   },
   //dot1xSuppEapolLogoffFramesTx object (1.0.8802.1.1.1.1.3.2.1.4)
   {
      "dot1xSuppEapolLogoffFramesTx",
      {40, 196, 98, 1, 1, 1, 1, 3, 2, 1, 4},
      11,
      ASN1_CLASS_APPLICATION,
      MIB_TYPE_COUNTER32,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      sizeof(uint32_t),
      NULL,
      ieee8021PaeMibGetDot1xSuppStatsEntry,
      ieee8021PaeMibGetNextDot1xSuppStatsEntry
   },
   //dot1xSuppInvalidEapolFramesRx object (1.0.8802.1.1.1.1.3.2.1.9)
   {
      "dot1xSuppInvalidEapolFramesRx",
      {40, 196, 98, 1, 1, 1, 1, 3, 2, 1, 9},
      11,
      ASN1_CLASS_APPLICATION,
      MIB_TYPE_COUNTER32,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      sizeof(uint32_t),
      NULL,
      ieee8021PaeMibGetDot1xSuppStatsEntry,
      ieee8021PaeMibGetNextDot1xSuppStatsEntry
   },
   //dot1xSuppEapLengthErrorFramesRx object (1.0.8802.1.1.1.1.3.2.1.10)
   {
      "dot1xSuppEapLengthErrorFramesRx",
      {40, 196, 98, 1, 1, 1, 1, 3, 2, 1, 10},
      11,
      ASN1_CLASS_APPLICATION,
      MIB_TYPE_COUNTER32,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      sizeof(uint32_t),
      NULL,
      ieee8021PaeMibGetDot1xSuppStatsEntry,
      ieee8021PaeMibGetNextDot1xSuppStatsEntry
   },
   //dot1xSuppLastEapolFrameVersion object (1.0.8802.1.1.1.1.3.2.1.11)
   {
      "dot1xSuppLastEapolFrameVersion",
      {40, 196, 98, 1, 1, 1, 1, 3, 2, 1, 11},
      11,
      ASN1_CLASS_APPLICATION,
      MIB_TYPE_UNSIGNED32,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      sizeof(uint32_t),
      NULL,
      ieee8021PaeMibGetDot1xSuppStatsEntry,
      ieee8021PaeMibGetNextDot1xSuppStatsEntry
   },
   //dot1xSuppLastEapolFrameSource object (1.0.8802.1.1.1.1.3.2.1.12)
   {
      "dot1xSuppLastEapolFrameSource",
      {40, 196, 98, 1, 1, 1, 1, 3, 2, 1, 12},
      11,
      ASN1_CLASS_UNIVERSAL,
      ASN1_TYPE_OCTET_STRING,
      MIB_ACCESS_READ_ONLY,
      NULL,
      NULL,
      0,
      NULL,
      ieee8021PaeMibGetDot1xSuppStatsEntry,
      ieee8021PaeMibGetNextDot1xSuppStatsEntry
   }
#endif
};


/**
 * @brief Port Access Control MIB module
 **/

const MibModule ieee8021PaeMibModule =
{
   "IEEE8021-PAE-MIB",
   {40, 196, 98, 1, 1, 1},
   6,
   ieee8021PaeMibObjects,
   arraysize(ieee8021PaeMibObjects),
   ieee8021PaeMibInit,
   NULL,
   NULL,
   ieee8021PaeMibLock,
   ieee8021PaeMibUnlock
};

#endif
