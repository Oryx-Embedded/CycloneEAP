/**
 * @file radius_debug.h
 * @brief Data logging functions for debugging purpose (RADIUS)
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

#ifndef _RADIUS_DEBUG_H
#define _RADIUS_DEBUG_H

//Dependencies
#include "radius/radius.h"
#include "radius/radius_attributes.h"
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
} RadiusParamName;


//RADIUS related functions
#if (RADIUS_TRACE_LEVEL >= TRACE_LEVEL_DEBUG)
   void radiusDumpPacket(const RadiusPacket *packet, size_t length);
#else
   #define radiusDumpPacket(packet, length)
#endif

void radiusDumpAttribute(const RadiusAttribute *attribute);

void radiusDumpInt32(const uint8_t *data, size_t length);
void radiusDumpString(const uint8_t *data, size_t length);
void radiusDumpIpv4Addr(const uint8_t *data, size_t length);
void radiusDumpIpv6Addr(const uint8_t *data, size_t length);
void radiusDumpRawData(const uint8_t *data, size_t length);

const char_t *radiusGetParamName(uint_t value, const RadiusParamName *paramList,
   size_t paramListLen);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
