/**
 * @file eap_peer_procedures.h
 * @brief EAP peer state machine procedures
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

#ifndef _EAP_PEER_PROCEDURES_H
#define _EAP_PEER_PROCEDURES_H

//Dependencies
#include "supplicant/supplicant.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//EAP related functions
void eapParseReq(SupplicantContext *context);
bool_t eapCheckReq(SupplicantContext *context);
void eapProcessReq(SupplicantContext *context);
void eapBuildResp(SupplicantContext *context);
void eapProcessIdentity(SupplicantContext *context);
void eapBuildIdentity(SupplicantContext *context);
void eapProcessNotify(SupplicantContext *context);
void eapBuildNotify(SupplicantContext *context);
void eapBuildNak(SupplicantContext *context);
uint8_t *eapPeerGetKey(SupplicantContext *context);
bool_t eapIsKeyAvailable(SupplicantContext *context);
bool_t eapAllowMethod(SupplicantContext *context, EapMethodType method);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
