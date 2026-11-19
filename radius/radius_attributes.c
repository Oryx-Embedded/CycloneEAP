/**
 * @file radius_attributes.c
 * @brief Formatting and parsing of RADIUS attributes
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
 * @version 2.6.6
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL RADIUS_TRACE_LEVEL

//Dependencies
#include "radius/radius.h"
#include "radius/radius_attributes.h"
#include "debug.h"

//Check EAP library configuration
#if (RADIUS_SUPPORT == ENABLED)


/**
 * @brief Append an attribute to a RADIUS packet
 * @param[in] packet Pointer to the RADIUS packet
 * @param[in] type Attribute type
 * @param[in] value Attribute value
 * @param[in] length Length of the attribute value
 **/

void radiusAddAttribute(RadiusPacket *packet, uint8_t type, const void *value,
   size_t length)
{
   size_t n;
   RadiusAttribute *attribute;

   //Check the length of the attribute value
   if(length > 0 && length <= RADIUS_MAX_ATTR_VALUE_LEN)
   {
      //Retrieve the actual length of the RADIUS packet
      n = ntohs(packet->length);

      //Point to the buffer where to format the RADIUS attribute
      attribute = (RadiusAttribute *) ((uint8_t *) packet + n);

      //The Type field is one octet
      attribute->type = type;

      //The Length field is one octet, and indicates the length of this Attribute
      //including the Type, Length and Value fields (refer to RFC 2865, section 5)
      attribute->length = sizeof(RadiusAttribute) + length;

      //Copy attribute value
      osMemcpy(attribute->value, value, length);

      //Adjust the length of the RADIUS packet
      n += attribute->length;
      //Fix the length field
      packet->length = htons(n);
   }
}


/**
 * @brief Search a RADIUS packet for a given attribute
 * @param[in] packet Pointer to the RADIUS packet
 * @param[in] type Attribute type
 * @param[in] index Attribute occurrence index
 * @return If the specified attribute is found, a pointer to the corresponding
 *   attribute is returned. Otherwise NULL pointer is returned
 **/

const RadiusAttribute *radiusGetAttribute(const RadiusPacket *packet,
   uint8_t type, uint_t index)
{
   uint_t k;
   size_t i;
   size_t n;
   const RadiusAttribute *attribute;

   //Retrieve the actual length of the RADIUS packet
   n = ntohs(packet->length);

   //Check the length of the RADIUS packet
   if(n > sizeof(RadiusPacket))
   {
      //Calculate the length of the RADIUS attributes
      n -= sizeof(RadiusPacket);

      //Initialize occurrence index
      k = 0;

      //Loop through the attributes
      for(i = 0; i < n; i += attribute->length)
      {
         //Point to the attribute
         attribute = (RadiusAttribute *) (packet->attributes + i);

         //Malformed attribute?
         if(attribute->length < sizeof(RadiusAttribute) ||
            attribute->length > (n - i))
         {
            return NULL;
         }

         //Matching attribute type?
         if(attribute->type == type)
         {
            //Matching occurrence found?
            if(k++ == index)
            {
               return attribute;
            }
         }
      }
   }

   //The specified attribute type was not found
   return NULL;
}

#endif

