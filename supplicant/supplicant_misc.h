/**
 * @file supplicant_misc.h
 * @brief Helper functions for 802.1X supplicant
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

#ifndef _SUPPLICANT_MISC_H
#define _SUPPLICANT_MISC_H

//Dependencies
#include "supplicant/supplicant.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//Supplicant related functions
void supplicantTick(SupplicantContext *context);
bool_t supplicantGetLinkState(SupplicantContext *context);

error_t supplicantAcceptPaeGroupAddr(SupplicantContext *context);
error_t supplicantDropPaeGroupAddr(SupplicantContext *context);

error_t supplicantSendEapolPdu(SupplicantContext *context, const uint8_t *pdu,
   size_t length);

void supplicantProcessEapolPdu(SupplicantContext *context);

void supplicantProcessEapPacket(SupplicantContext *context,
   const EapPacket *packet, size_t length);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
