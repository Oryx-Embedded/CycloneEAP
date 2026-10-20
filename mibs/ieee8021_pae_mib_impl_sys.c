/**
 * @file ieee8021_pae_mib_impl.c (dot1xPaeSystem subtree)
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
#if (IEEE8021_PAE_MIB_SUPPORT == ENABLED && AUTHENTICATOR_SUPPORT == ENABLED)


/**
 * @brief Set dot1xPaeSystemAuthControl object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[in] value Object value
 * @param[in] valueLen Length of the object value, in bytes
 * @param[in] commit This flag tells whether the changes shall be committed
 *   to the MIB base
 * @return Error code
 **/

error_t ieee8021PaeMibSetDot1xPaeSystemAuthControl(const MibObject *object, const uint8_t *oid,
   size_t oidLen, const MibVariant *value, size_t valueLen, bool_t commit)
{
#if (IEEE8021_PAE_MIB_SET_SUPPORT == ENABLED)
   error_t error;

   //This object forces the administrative enable/disable state for port
   //access control
   if(value->integer == IEEE8021_PAE_MIB_SYS_AUTH_CONTROL_ENABLED ||
      value->integer == IEEE8021_PAE_MIB_SYS_AUTH_CONTROL_DISABLED)
   {
      //Not implemented
      error = NO_ERROR;
   }
   else
   {
      //Report an error
      error = ERROR_WRONG_VALUE;
   }

   //Return status code
   return error;
#else
   //SET operation is not supported
   return ERROR_WRITE_FAILED;
#endif
}


/**
 * @brief Get dot1xPaeSystemAuthControl object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] value Object value
 * @param[in,out] valueLen Length of the object value, in bytes
 * @return Error code
 **/

error_t ieee8021PaeMibGetDot1xPaeSystemAuthControl(const MibObject *object, const uint8_t *oid,
   size_t oidLen, MibVariant *value, size_t *valueLen)
{
   //Return the administrative enable/disable state for port access control
   if(ieee8021PaeMibBase.authContext->running)
   {
      value->integer = IEEE8021_PAE_MIB_SYS_AUTH_CONTROL_ENABLED;
   }
   else
   {
      value->integer = IEEE8021_PAE_MIB_SYS_AUTH_CONTROL_DISABLED;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set dot1xPaePortEntry object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[in] value Object value
 * @param[in] valueLen Length of the object value, in bytes
 * @param[in] commit This flag tells whether the changes shall be committed
 *   to the MIB base
 * @return Error code
 **/

error_t ieee8021PaeMibSetDot1xPaePortEntry(const MibObject *object, const uint8_t *oid,
   size_t oidLen, const MibVariant *value, size_t valueLen, bool_t commit)
{
#if (IEEE8021_PAE_MIB_SET_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   uint_t dot1xPaePortNumber;

   //Point to the instance identifier
   n = object->oidLen;

   //dot1xPaePortNumber is used as instance identifier
   error = mibDecodeIndex(oid, oidLen, &n, &dot1xPaePortNumber);
   //Invalid instance identifier?
   if(error)
   {
      return error;
   }

   //Sanity check
   if(n != oidLen)
   {
      return ERROR_INSTANCE_NOT_FOUND;
   }

   //dot1xPaePortInitialize object?
   if(osStrcmp(object->name, "dot1xPaePortInitialize") == 0)
   {
      //Initialization control for this port
      if(value->integer == MIB_TRUTH_VALUE_TRUE)
      {
         //Setting this attribute TRUE causes the port to be initialized
         error = authenticatorMgmtSetInitialize(ieee8021PaeMibBase.authContext,
            dot1xPaePortNumber, TRUE, commit);
      }
      else if(value->integer == MIB_TRUTH_VALUE_FALSE)
      {
         //Setting this attribute FALSE has no effect
         error = NO_ERROR;
      }
      else
      {
         //Report an error
         error = ERROR_WRONG_VALUE;
      }
   }
   //dot1xPaePortReauthenticate object?
   else if(osStrcmp(object->name, "dot1xPaePortReauthenticate") == 0)
   {
      //Reauthentication control for this port
      if(value->integer == MIB_TRUTH_VALUE_TRUE)
      {
         //Setting this attribute TRUE causes the authenticator PAE state
         //machine for the port to reauthenticate the supplicant
         error = authenticatorMgmtSetReauthenticate(ieee8021PaeMibBase.authContext,
            dot1xPaePortNumber, TRUE, commit);
      }
      else if(value->integer == MIB_TRUTH_VALUE_FALSE)
      {
         //Setting this attribute FALSE has no effect
         error = NO_ERROR;
      }
      else
      {
         //Report an error
         error = ERROR_WRONG_VALUE;
      }
   }
   //Unknown object?
   else
   {
      //The specified object does not exist
      error = ERROR_OBJECT_NOT_FOUND;
   }

   //Return status code
   return error;
#else
   //SET operation is not supported
   return ERROR_WRITE_FAILED;
#endif
}


/**
 * @brief Get dot1xPaePortEntry object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] value Object value
 * @param[in,out] valueLen Length of the object value, in bytes
 * @return Error code
 **/

error_t ieee8021PaeMibGetDot1xPaePortEntry(const MibObject *object, const uint8_t *oid,
   size_t oidLen, MibVariant *value, size_t *valueLen)
{
   error_t error;
   size_t n;
   uint_t dot1xPaePortNumber;

   //Point to the instance identifier
   n = object->oidLen;

   //dot1xPaePortNumber is used as instance identifier
   error = mibDecodeIndex(oid, oidLen, &n, &dot1xPaePortNumber);
   //Invalid instance identifier?
   if(error)
   {
      return error;
   }

   //Sanity check
   if(n != oidLen)
   {
      return ERROR_INSTANCE_NOT_FOUND;
   }

   //dot1xPaePortProtocolVersion object?
   if(osStrcmp(object->name, "dot1xPaePortProtocolVersion") == 0)
   {
      //This object indicates the protocol version associated with this port
      value->unsigned32 = EAPOL_VERSION_2;
   }
   //dot1xPaePortCapabilities object?
   else if(osStrcmp(object->name, "dot1xPaePortCapabilities") == 0)
   {
      //This object  indicates the PAE functionality that this port supports
      //and that may be managed through this MIB
      value->octetString[0] = reverseInt8(IEEE8021_PAE_MIB_PORT_CAP_AUTH);
      //Return object length
      *valueLen = sizeof(uint8_t);
   }
   //dot1xPaePortInitialize object?
   else if(osStrcmp(object->name, "dot1xPaePortInitialize") == 0)
   {
      //The attribute value reverts to FALSE once initialization has completed
      value->integer = 0;
   }
   //dot1xPaePortReauthenticate object?
   else if(osStrcmp(object->name, "dot1xPaePortReauthenticate") == 0)
   {
      //This attribute always returns FALSE when it is read
      value->integer = 0;
   }
   //Unknown object?
   else
   {
      //The specified object does not exist
      error = ERROR_OBJECT_NOT_FOUND;
   }

   //Return status code
   return error;
}


/**
 * @brief Get next dot1xPaePortEntry object
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] nextOid OID of the next object in the MIB
 * @param[out] nextOidLen Length of the next object identifier, in bytes
 * @return Error code
 **/

error_t ieee8021PaeMibGetNextDot1xPaePortEntry(const MibObject *object, const uint8_t *oid,
   size_t oidLen, uint8_t *nextOid, size_t *nextOidLen)
{
   error_t error;
   uint_t i;
   size_t n;
   uint16_t portNum;
   uint16_t curPortNum;
   AuthenticatorContext *context;

   //Initialize variable
   portNum = 0;

   //Point to the 802.1X authenticator context
   context = ieee8021PaeMibBase.authContext;
   //Make sure the context is valid
   if(context == NULL)
   {
      return ERROR_OBJECT_NOT_FOUND;
   }

   //Make sure the buffer is large enough to hold the OID prefix
   if(*nextOidLen < object->oidLen)
   {
      return ERROR_BUFFER_OVERFLOW;
   }

   //Copy OID prefix
   osMemcpy(nextOid, object->oid, object->oidLen);

   //Loop through the ports of the bridge
   for(i = 0; i < context->numPorts; i++)
   {
      //Retrieve the port number associated with the current port
      curPortNum = context->ports[i].portIndex;

      //Append the instance identifier to the OID prefix
      n = object->oidLen;

      //dot1xPaePortNumber is used as instance identifier
      error = mibEncodeIndex(nextOid, *nextOidLen, &n, curPortNum);
      //Any error to report?
      if(error)
      {
         return error;
      }

      //Check whether the resulting object identifier lexicographically
      //follows the specified OID
      if(oidComp(nextOid, n, oid, oidLen) > 0)
      {
         //Save the closest object identifier that follows the specified
         //OID in lexicographic order
         if(portNum == 0 || curPortNum < portNum)
         {
            portNum = curPortNum;
         }
      }
   }

   //The specified OID does not lexicographically precede the name
   //of some object?
   if(portNum == 0)
   {
      return ERROR_OBJECT_NOT_FOUND;
   }

   //Append the instance identifier to the OID prefix
   n = object->oidLen;

   //dot1xPaePortNumber is used as instance identifier
   error = mibEncodeIndex(nextOid, *nextOidLen, &n, portNum);
   //Any error to report?
   if(error)
   {
      return error;
   }

   //Save the length of the resulting object identifier
   *nextOidLen = n;
   //Next object found
   return NO_ERROR;
}

#endif
