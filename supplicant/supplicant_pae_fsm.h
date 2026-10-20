/**
 * @file supplicant_pae_fsm.h
 * @brief Supplicant PAE state machine
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

#ifndef _SUPPLICANT_PAE_FSM_H
#define _SUPPLICANT_PAE_FSM_H

//Dependencies
#include "supplicant/supplicant.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Supplicant PAE states
 **/

typedef enum
{
   SUPPLICANT_PAE_STATE_LOGOFF          = 0,
   SUPPLICANT_PAE_STATE_DISCONNECTED    = 1,
   SUPPLICANT_PAE_STATE_CONNECTING      = 2,
   SUPPLICANT_PAE_STATE_AUTHENTICATING  = 3,
   SUPPLICANT_PAE_STATE_AUTHENTICATED   = 4,
   SUPPLICANT_PAE_STATE_HELD            = 5,
   SUPPLICANT_PAE_STATE_RESTART         = 6,
   SUPPLICANT_PAE_STATE_S_FORCE_AUTH    = 7,
   SUPPLICANT_PAE_STATE_S_FORCE_UNAUTH  = 8
} SupplicantPaeState;


/**
 * @brief Port status
 **/

typedef enum
{
   SUPPLICANT_PORT_STATUS_UNAUTH = 0,
   SUPPLICANT_PORT_STATUS_AUTH   = 1
} SupplicantPortStatus;


/**
 * @brief Port modes
 **/

typedef enum
{
   SUPPLICANT_PORT_MODE_FORCE_UNAUTH = 0,
   SUPPLICANT_PORT_MODE_FORCE_AUTH   = 1,
   SUPPLICANT_PORT_MODE_AUTO         = 2
} SupplicantPortMode;


//Supplicant related functions
void supplicantPaeInitFsm(SupplicantContext *context);
void supplicantPaeFsm(SupplicantContext *context);

void supplicantPaeChangeState(SupplicantContext *context,
   SupplicantPaeState newState);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
