/**
 * @file eap_mschapv2.h
 * @brief EAP MS-CHAP-V2 authentication method
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

#ifndef _EAP_MSCHAPV2_H
#define _EAP_MSCHAPV2_H

//Dependencies
#include "eap/eap.h"
#include "supplicant/supplicant.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//EAP MS-CHAP-V2 related functions
error_t eapMschapv2CheckRequest(SupplicantContext *context,
   const EapMschapv2Packet *request, size_t length);

void eapMschapv2ProcessRequest(SupplicantContext *context,
   const EapMschapv2Packet *request, size_t length);

void eapMschapv2BuildResponse(SupplicantContext *context);

void eapMschapv2GenerateNtResponse(const uint8_t *authChallenge,
   const uint8_t *peerChallenge, const char_t *username,
   const char_t *password, uint8_t *response);

void eapMschapv2ChallengeHash(const uint8_t *peerChallenge,
   const uint8_t *authChallenge, const char_t *username, uint8_t *challenge);

void eapMschapv2NtPasswordHash(const char_t *password, uint8_t *passwordHash);

void eapMschapv2HashNtPasswordHash(const uint8_t *passwordHash,
   uint8_t *passwordHashHash);

void eapMschapv2ChallengeResponse(const uint8_t *challenge,
   const uint8_t *passwordHash, uint8_t *response);

void eapMschapv2GenerateAuthResponse(const char_t *password,
   const uint8_t *ntResponse, const uint8_t *peerChallenge,
   const uint8_t *authChallenge, const char_t *username, uint8_t *authResponse);

bool_t eapMschapv2CheckAuthResponse(const char_t *password,
   const uint8_t *ntResponse, const uint8_t *peerChallenge,
   const uint8_t *authChallenge, const char_t *username,
   const uint8_t *receivedResponse);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
