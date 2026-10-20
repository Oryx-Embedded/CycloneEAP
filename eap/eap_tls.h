/**
 * @file eap_tls.h
 * @brief EAP-TLS authentication method
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

#ifndef _EAP_TLS_H
#define _EAP_TLS_H

//Dependencies
#include "eap/eap.h"
#include "supplicant/supplicant.h"

//Offset to the TLS data field
#define EAP_TLS_TX_BUFFER_START_POS (sizeof(EapolPdu) + \
   sizeof(EapTlsPacket) + sizeof(uint32_t))

//Maximum fragment size (for first fragment)
#define EAP_TLS_MAX_INIT_FRAG_SIZE (EAP_MAX_FRAG_SIZE - sizeof(EapolPdu) - \
   sizeof(EapTlsPacket) - sizeof(uint32_t))

//Maximum fragment size (for subsequent fragments)
#define EAP_TLS_MAX_FRAG_SIZE (EAP_MAX_FRAG_SIZE - sizeof(EapolPdu) - \
   sizeof(EapTlsPacket))


//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//EAP-TLS related functions
error_t eapTlsCheckRequest(SupplicantContext *context,
   const EapTlsPacket *request, size_t length);

void eapTlsProcessRequest(SupplicantContext *context,
   const EapTlsPacket *request, size_t length);

void eapTlsBuildResponse(SupplicantContext *context);

error_t eapOpenTls(SupplicantContext *context);
void eapCloseTls(SupplicantContext *context, error_t error);

error_t eapTlsSendCallback(void *handle, const void *data, size_t length,
   size_t *written, uint_t flags);

error_t eapTlsReceiveCallback(void *handle, void *data, size_t size,
   size_t *received, uint_t flags);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
