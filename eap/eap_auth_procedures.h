/**
 * @file eap_auth_procedures.h
 * @brief EAP authenticator state machine procedures
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

#ifndef _EAP_AUTH_PROCEDURES_H
#define _EAP_AUTH_PROCEDURES_H

//Dependencies
#include "authenticator/authenticator.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//EAP related functions
uint_t eapCalculateTimeout(AuthenticatorPort *port);
void eapParseResp(AuthenticatorPort *port);
void eapBuildSuccess(AuthenticatorPort *port);
void eapBuildFailure(AuthenticatorPort *port);
uint_t eapNextId(uint_t id);

void eapPolicyUpdate(AuthenticatorPort *port);
EapMethodType eapPolicyGetNextMethod(AuthenticatorPort *port);
EapDecision eapPolicyGetDecision(AuthenticatorPort *port);

bool_t eapCheckResp(AuthenticatorPort *port);
void eapProcessResp(AuthenticatorPort *port);
void eapInit(AuthenticatorPort *port);
void eapReset(AuthenticatorPort *port);
bool_t eapIsDone(AuthenticatorPort *port);
uint_t eapGetTimeout(AuthenticatorPort *port);
uint8_t *eapAuthGetKey(AuthenticatorPort *port);
void eapBuildReq(AuthenticatorPort *port);

uint_t eapGetId(const uint8_t *eapReqData, size_t eapReqDataLen);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
