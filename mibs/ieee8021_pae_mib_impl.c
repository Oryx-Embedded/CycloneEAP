/**
 * @file ieee8021_pae_mib_impl.c
 * @brief Port Access Control MIB module implementation
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
#include "core/crypto.h"
#include "encoding/asn1.h"
#include "encoding/oid.h"
#include "authenticator/authenticator_mgmt.h"
#include "debug.h"

//Check TCP/IP stack configuration
#if (IEEE8021_PAE_MIB_SUPPORT == ENABLED)


/**
 * @brief Port Access Control MIB module initialization
 * @return Error code
 **/

error_t ieee8021PaeMibInit(void)
{
   //Debug message
   TRACE_INFO("Initializing Port Access Control MIB base...\r\n");

   //Clear Port Access Control MIB base
   memset(&ieee8021PaeMibBase, 0, sizeof(ieee8021PaeMibBase));

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Lock Port Access Control MIB base
 **/

void ieee8021PaeMibLock(void)
{
   //Acquire exclusive access to the 802.1X authenticator context
   authenticatorMgmtLock(ieee8021PaeMibBase.authContext);
}


/**
 * @brief Unlock Port Access Control MIB base
 **/

void ieee8021PaeMibUnlock(void)
{
   //Release exclusive access to the 802.1X authenticator context
   authenticatorMgmtUnlock(ieee8021PaeMibBase.authContext);
}


/**
 * @brief Attach 802.1X authenticator context
 * @param[in] context Pointer to the 802.1X authenticator context
 * @return Error code
 **/

error_t ieee8021PaeMibSetAuthenticatorContext(AuthenticatorContext *context)
{
   //Attach 802.1X authenticator context
   ieee8021PaeMibBase.authContext = context;

   //Successful processing
   return NO_ERROR;
}

#endif
