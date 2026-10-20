/**
 * @file eap_debug.h
 * @brief Data logging functions for debugging purpose (EAP)
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

#ifndef _EAP_DEBUG_H
#define _EAP_DEBUG_H

//Dependencies
#include "eap/eap.h"
#include "debug.h"


//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Parameter value/name binding
 **/

typedef struct
{
   uint_t value;
   const char_t *name;
} EapParamName;


//EAP related functions
#if (EAP_TRACE_LEVEL >= TRACE_LEVEL_DEBUG)
   void eapolDumpHeader(const EapolPdu *header);
   void eapDumpPacket(const EapPacket *packet, size_t length);
#else
   #define eapolDumpHeader(header)
   #define eapDumpPacket(packet, length)
#endif

void eapDumpHeader(const EapPacket *header);

void eapDumpRequest(const EapRequest *request, size_t length);
void eapDumpResponse(const EapResponse *response, size_t length);

void eapDumpIdentityRequest(const EapRequest *request, size_t length);
void eapDumpIdentityResponse(const EapResponse *response, size_t length);

void eapDumpNakResponse(const EapResponse *response, size_t length);

void eapMd5DumpPacket(const EapMd5Packet *packet, size_t length);

void eapMschapv2DumpPacket(const EapMschapv2Packet *packet, size_t length);

void eapMschapv2DumpChallenge(const EapMschapv2Challenge *challenge,
   size_t length);

void eapMschapv2DumpResponse(const EapMschapv2Response *response,
   size_t length);

void eapMschapv2DumpSuccessRequest(const EapMschapv2SuccessRequest *request,
   size_t length);

void eapMschapv2DumpSuccessResponse(const EapMschapv2SuccessResponse *response,
   size_t length);

void eapMschapv2DumpFailureRequest(const EapMschapv2FailureRequest *request,
   size_t length);

void eapMschapv2DumpFailureResponse(const EapMschapv2FailureResponse *response,
   size_t length);

void eapTlsDumpPacket(const EapTlsPacket *packet, size_t length);
void eapTlsDumpFlags(uint8_t flags);

void eapDumpString(const uint8_t *s, size_t length);

const char_t *eapGetParamName(uint_t value, const EapParamName *paramList,
   size_t paramListLen);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
