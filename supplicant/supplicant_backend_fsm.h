/**
 * @file supplicant_backend_fsm.h
 * @brief Supplicant backend state machine
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

#ifndef _SUPPLICANT_BACKEND_FSM_H
#define _SUPPLICANT_BACKEND_FSM_H

//Dependencies
#include "supplicant/supplicant.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Supplicant backend states
 **/

typedef enum
{
   SUPPLICANT_BACKEND_STATE_INITIALIZE = 0,
   SUPPLICANT_BACKEND_STATE_IDLE       = 1,
   SUPPLICANT_BACKEND_STATE_REQUEST    = 2,
   SUPPLICANT_BACKEND_STATE_RESPONSE   = 3,
   SUPPLICANT_BACKEND_STATE_RECEIVE    = 4,
   SUPPLICANT_BACKEND_STATE_FAIL       = 5,
   SUPPLICANT_BACKEND_STATE_TIMEOUT    = 6,
   SUPPLICANT_BACKEND_STATE_SUCCESS    = 7
} SupplicantBackendState;


//Supplicant related functions
void supplicantBackendInitFsm(SupplicantContext *context);
void supplicantBackendFsm(SupplicantContext *context);

void supplicantBackendChangeState(SupplicantContext *context,
   SupplicantBackendState newState);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
