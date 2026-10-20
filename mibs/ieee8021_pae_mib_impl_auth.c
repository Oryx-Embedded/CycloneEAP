/**
 * @file ieee8021_pae_mib_impl.c (dot1xPaeAuthenticator subtree)
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
 * @brief Set dot1xAuthConfigEntry object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[in] value Object value
 * @param[in] valueLen Length of the object value, in bytes
 * @param[in] commit This flag tells whether the changes shall be committed
 *   to the MIB base
 * @return Error code
 **/

error_t ieee8021PaeMibSetDot1xAuthConfigEntry(const MibObject *object, const uint8_t *oid,
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

   //dot1xAuthAdminControlledDirections object?
   if(osStrcmp(object->name, "dot1xAuthAdminControlledDirections") == 0)
   {
      //This object specifies the value of the administrative controlled
      //directions parameter for the port
      if(value->integer == IEEE8021_PAE_MIB_CONTROL_DIR_BOTH ||
         value->integer == IEEE8021_PAE_MIB_CONTROL_DIR_IN)
      {
         //Not implemented
         error = NO_ERROR;
      }
      else
      {
         //Report an error
         error = ERROR_WRONG_VALUE;
      }
   }
   //dot1xAuthAuthControlledPortControl object?
   else if(osStrcmp(object->name, "dot1xAuthAuthControlledPortControl") == 0)
   {
      //This object specifies the value of the controlled port control
      //parameter for the port
      if(value->integer == IEEE8021_PAE_MIB_PORT_CONTROL_FORCE_UNAUTH)
      {
         //The controlled port is required to be held in the Unauthorized state
         error = authenticatorMgmtSetPortControl(ieee8021PaeMibBase.authContext,
            dot1xPaePortNumber, AUTHENTICATOR_PORT_MODE_FORCE_UNAUTH, commit);
      }
      else if(value->integer == IEEE8021_PAE_MIB_PORT_CONTROL_FORCE_AUTH)
      {
         //The controlled port is required to be held in the Authorized state
         error = authenticatorMgmtSetPortControl(ieee8021PaeMibBase.authContext,
            dot1xPaePortNumber, AUTHENTICATOR_PORT_MODE_FORCE_AUTH, commit);
      }
      else if(value->integer == IEEE8021_PAE_MIB_PORT_CONTROL_AUTO)
      {
         //The controlled port is set to the Authorized or Unauthorized state
         //in accordance with the outcome of an authentication exchange between
         //the supplicant and the authentication server
         error = authenticatorMgmtSetPortControl(ieee8021PaeMibBase.authContext,
            dot1xPaePortNumber, AUTHENTICATOR_PORT_MODE_AUTO, commit);
      }
      else
      {
         //Report an error
         error = ERROR_WRONG_VALUE;
      }
   }
   //dot1xAuthQuietPeriod object?
   else if(osStrcmp(object->name, "dot1xAuthQuietPeriod") == 0)
   {
      //This object specifies the value, in seconds, of the quietPeriod constant
      //currently in use by the authenticator PAE state machine
      error = authenticatorMgmtSetQuietPeriod(ieee8021PaeMibBase.authContext,
         dot1xPaePortNumber, value->unsigned32, commit);
   }
   //dot1xAuthServerTimeout object?
   else if(osStrcmp(object->name, "dot1xAuthServerTimeout") == 0)
   {
      //This object specifies The value, in seconds, of the serverTimeout
      //constant currently in use by the backend authentication state machine
      error = authenticatorMgmtSetServerTimeout(ieee8021PaeMibBase.authContext,
         dot1xPaePortNumber, value->unsigned32, commit);
   }
   //dot1xAuthReAuthPeriod object?
   else if(osStrcmp(object->name, "dot1xAuthReAuthPeriod") == 0)
   {
      //This object specifies the value, in seconds, of the reAuthPeriod
      //constant currently in use by the reauthentication timer state machine
      error = authenticatorMgmtSetReAuthPeriod(ieee8021PaeMibBase.authContext,
         dot1xPaePortNumber, value->unsigned32, commit);
   }
   //dot1xAuthReAuthEnabled object?
   else if(osStrcmp(object->name, "dot1xAuthReAuthEnabled") == 0)
   {
      //This object specifies the enable/disable control used by the
      //reauthentication timer state machine
      if(value->integer == MIB_TRUTH_VALUE_TRUE)
      {
         //Enable reauthentication
         error = authenticatorMgmtSetReAuthEnabled(ieee8021PaeMibBase.authContext,
            dot1xPaePortNumber, TRUE, commit);
      }
      else if(value->integer == MIB_TRUTH_VALUE_FALSE)
      {
         //Disable reauthentication
         error = authenticatorMgmtSetReAuthEnabled(ieee8021PaeMibBase.authContext,
            dot1xPaePortNumber, FALSE, commit);
      }
      else
      {
         //Report an error
         error = ERROR_WRONG_VALUE;
      }
   }
   //dot1xAuthKeyTxEnabled object?
   else if(osStrcmp(object->name, "dot1xAuthKeyTxEnabled") == 0)
   {
      //This object specifies the value of the keyTransmissionEnabled constant
      //currently in use by the authenticator PAE state machine
      if(value->integer == MIB_TRUTH_VALUE_TRUE)
      {
         //Enable transmission of key information
         error = authenticatorMgmtSetKeyTxEnabled(ieee8021PaeMibBase.authContext,
            dot1xPaePortNumber, TRUE, commit);
      }
      else if(value->integer == MIB_TRUTH_VALUE_FALSE)
      {
         //Disable transmission of key information
         error = authenticatorMgmtSetKeyTxEnabled(ieee8021PaeMibBase.authContext,
            dot1xPaePortNumber, FALSE, commit);
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
 * @brief Get dot1xAuthConfigEntry object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] value Object value
 * @param[in,out] valueLen Length of the object value, in bytes
 * @return Error code
 **/

error_t ieee8021PaeMibGetDot1xAuthConfigEntry(const MibObject *object, const uint8_t *oid,
   size_t oidLen, MibVariant *value, size_t *valueLen)
{
   error_t error;
   size_t n;
   uint_t dot1xPaePortNumber;
   AuthenticatorContext *context;
   AuthenticatorPort *port;

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

   //Point to the 802.1X authenticator context
   context = (AuthenticatorContext *) ieee8021PaeMibBase.authContext;
   //Sanity check
   if(context == NULL)
   {
      return ERROR_INSTANCE_NOT_FOUND;
   }

   //Invalid port index?
   if(dot1xPaePortNumber < 1 || dot1xPaePortNumber > context->numPorts)
   {
      return ERROR_INSTANCE_NOT_FOUND;
   }

   //Point to the port that matches the specified port index
   port = &context->ports[dot1xPaePortNumber - 1];

   //dot1xAuthPaeState object?
   if(osStrcmp(object->name, "dot1xAuthPaeState") == 0)
   {
      //This object indicates the current value of the authenticator PAE state
      switch(port->authPaeState)
      {
      case AUTHENTICATOR_PAE_STATE_INITIALIZE:
         value->integer = IEEE8021_PAE_MIB_AUTH_PAE_STATE_INITIALIZE;
         break;
      case AUTHENTICATOR_PAE_STATE_DISCONNECTED:
         value->integer = IEEE8021_PAE_MIB_AUTH_PAE_STATE_DISCONNECTED;
         break;
      case AUTHENTICATOR_PAE_STATE_CONNECTING:
         value->integer = IEEE8021_PAE_MIB_AUTH_PAE_STATE_CONNECTING;
         break;
      case AUTHENTICATOR_PAE_STATE_AUTHENTICATING:
         value->integer = IEEE8021_PAE_MIB_AUTH_PAE_STATE_AUTHENTICATING;
         break;
      case AUTHENTICATOR_PAE_STATE_AUTHENTICATED:
         value->integer = IEEE8021_PAE_MIB_AUTH_PAE_STATE_AUTHENTICATED;
         break;
      case AUTHENTICATOR_PAE_STATE_ABORTING:
         value->integer = IEEE8021_PAE_MIB_AUTH_PAE_STATE_ABORTING;
         break;
      case AUTHENTICATOR_PAE_STATE_HELD:
         value->integer = IEEE8021_PAE_MIB_AUTH_PAE_STATE_HELD;
         break;
      case AUTHENTICATOR_PAE_STATE_FORCE_AUTH:
         value->integer = IEEE8021_PAE_MIB_AUTH_PAE_STATE_FORCE_AUTH;
         break;
      case AUTHENTICATOR_PAE_STATE_FORCE_UNAUTH:
         value->integer = IEEE8021_PAE_MIB_AUTH_PAE_STATE_FORCE_UNAUTH;
         break;
      case AUTHENTICATOR_PAE_STATE_RESTART:
         value->integer = IEEE8021_PAE_MIB_AUTH_PAE_STATE_RESTART;
         break;
      default:
         value->integer = 0;
         break;
      }
   }
   //dot1xAuthBackendAuthState object?
   else if(osStrcmp(object->name, "dot1xAuthBackendAuthState") == 0)
   {
      //This object indicates the current value of the backend authentication
      //state machine
      switch(port->authBackendState)
      {
      case AUTHENTICATOR_BACKEND_STATE_REQUEST:
         value->integer = IEEE8021_PAE_MIB_AUTH_BACKEND_STATE_REQUEST;
         break;
      case AUTHENTICATOR_BACKEND_STATE_RESPONSE:
         value->integer = IEEE8021_PAE_MIB_AUTH_BACKEND_STATE_RESPONSE;
         break;
      case AUTHENTICATOR_BACKEND_STATE_SUCCESS:
         value->integer = IEEE8021_PAE_MIB_AUTH_BACKEND_STATE_SUCCESS;
         break;
      case AUTHENTICATOR_BACKEND_STATE_FAIL:
         value->integer = IEEE8021_PAE_MIB_AUTH_BACKEND_STATE_FAIL;
         break;
      case AUTHENTICATOR_BACKEND_STATE_TIMEOUT:
         value->integer = IEEE8021_PAE_MIB_AUTH_BACKEND_STATE_TIMEOUT;
         break;
      case AUTHENTICATOR_BACKEND_STATE_IDLE:
         value->integer = IEEE8021_PAE_MIB_AUTH_BACKEND_STATE_IDLE;
         break;
      case AUTHENTICATOR_BACKEND_STATE_INITIALIZE:
         value->integer = IEEE8021_PAE_MIB_AUTH_BACKEND_STATE_INITIALIZE;
         break;
      case AUTHENTICATOR_BACKEND_STATE_IGNORE:
         value->integer = IEEE8021_PAE_MIB_AUTH_BACKEND_STATE_IGNORE;
         break;
      default:
         value->integer = 0;
         break;
      }
   }
   //dot1xAuthAdminControlledDirections object?
   else if(osStrcmp(object->name, "dot1xAuthAdminControlledDirections") == 0)
   {
      //This object indicates the current value of the administrative
      //controlled directions parameter for the port
      value->integer = IEEE8021_PAE_MIB_CONTROL_DIR_BOTH;
   }
   //dot1xAuthOperControlledDirections object?
   else if(osStrcmp(object->name, "dot1xAuthOperControlledDirections") == 0)
   {
      //This object indicates the current value of the operational controlled
      //directions parameter for the port
      value->integer = IEEE8021_PAE_MIB_CONTROL_DIR_BOTH;
   }
   //dot1xAuthAuthControlledPortStatus object?
   else if(osStrcmp(object->name, "dot1xAuthAuthControlledPortStatus") == 0)
   {
      //This object indicates the current value of the controlled port status
      //parameter for the port
      switch(port->authPortStatus)
      {
      case AUTHENTICATOR_PORT_STATUS_UNAUTH:
         value->integer = IEEE8021_PAE_MIB_PORT_STATUS_UNAUTH;
         break;
      case AUTHENTICATOR_PORT_STATUS_AUTH:
         value->integer = IEEE8021_PAE_MIB_PORT_STATUS_AUTH;
         break;
      default:
         value->integer = 0;
         break;
      }
   }
   //dot1xAuthAuthControlledPortControl object?
   else if(osStrcmp(object->name, "dot1xAuthAuthControlledPortControl") == 0)
   {
      //This object indicates the current value of the controlled port control
      //parameter for the port
      switch(port->portControl)
      {
      case AUTHENTICATOR_PORT_MODE_FORCE_UNAUTH:
         value->integer = IEEE8021_PAE_MIB_PORT_CONTROL_FORCE_UNAUTH;
         break;
      case AUTHENTICATOR_PORT_MODE_FORCE_AUTH:
         value->integer = IEEE8021_PAE_MIB_PORT_CONTROL_FORCE_AUTH;
         break;
      case AUTHENTICATOR_PORT_MODE_AUTO:
         value->integer = IEEE8021_PAE_MIB_PORT_CONTROL_AUTO;
         break;
      default:
         value->integer = 0;
         break;
      }
   }
   //dot1xAuthQuietPeriod object?
   else if(osStrcmp(object->name, "dot1xAuthQuietPeriod") == 0)
   {
      //This object indicates the value, in seconds, of the quietPeriod constant
      //currently in use by the authenticator PAE state machine
      value->unsigned32 = port->quietPeriod;
   }
   //dot1xAuthServerTimeout object?
   else if(osStrcmp(object->name, "dot1xAuthServerTimeout") == 0)
   {
      //This object indicates The value, in seconds, of the serverTimeout
      //constant currently in use by the backend authentication state machine
      value->unsigned32 = port->serverTimeout;
   }
   //dot1xAuthReAuthPeriod object?
   else if(osStrcmp(object->name, "dot1xAuthReAuthPeriod") == 0)
   {
      //This object indicates the value, in seconds, of the reAuthPeriod
      //constant currently in use by the reauthentication timer state machine
      value->unsigned32 = port->reAuthPeriod;
   }
   //dot1xAuthReAuthEnabled object?
   else if(osStrcmp(object->name, "dot1xAuthReAuthEnabled") == 0)
   {
      //This object indicates the enable/disable control used by the
      //reauthentication timer state machine
      if(port->reAuthEnabled)
      {
         value->integer = MIB_TRUTH_VALUE_TRUE;
      }
      else
      {
         value->integer = MIB_TRUTH_VALUE_FALSE;
      }
   }
   //dot1xAuthKeyTxEnabled object?
   else if(osStrcmp(object->name, "dot1xAuthKeyTxEnabled") == 0)
   {
      //This object indicates the value of the keyTransmissionEnabled constant
      //currently in use by the authenticator PAE state machine
      if(port->keyTxEnabled)
      {
         value->integer = MIB_TRUTH_VALUE_TRUE;
      }
      else
      {
         value->integer = MIB_TRUTH_VALUE_FALSE;
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
}


/**
 * @brief Get next dot1xAuthConfigEntry object
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] nextOid OID of the next object in the MIB
 * @param[out] nextOidLen Length of the next object identifier, in bytes
 * @return Error code
 **/

error_t ieee8021PaeMibGetNextDot1xAuthConfigEntry(const MibObject *object, const uint8_t *oid,
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


/**
 * @brief Get dot1xAuthStatsEntry object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] value Object value
 * @param[in,out] valueLen Length of the object value, in bytes
 * @return Error code
 **/

error_t ieee8021PaeMibGetDot1xAuthStatsEntry(const MibObject *object, const uint8_t *oid,
   size_t oidLen, MibVariant *value, size_t *valueLen)
{
   error_t error;
   size_t n;
   uint_t dot1xPaePortNumber;
   AuthenticatorContext *context;
   AuthenticatorPort *port;

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

   //Point to the 802.1X authenticator context
   context = (AuthenticatorContext *) ieee8021PaeMibBase.authContext;
   //Sanity check
   if(context == NULL)
   {
      return ERROR_INSTANCE_NOT_FOUND;
   }

   //Invalid port index?
   if(dot1xPaePortNumber < 1 || dot1xPaePortNumber > context->numPorts)
   {
      return ERROR_INSTANCE_NOT_FOUND;
   }

   //Point to the port that matches the specified port index
   port = &context->ports[dot1xPaePortNumber - 1];

   //dot1xAuthEapolFramesRx object?
   if(osStrcmp(object->name, "dot1xAuthEapolFramesRx") == 0)
   {
      //Number of valid EAPOL frames of any type that have been received by this
      //authenticator
      value->counter32 = port->stats.eapolFramesRx;
   }
   //dot1xAuthEapolFramesTx object?
   else if(osStrcmp(object->name, "dot1xAuthEapolFramesTx") == 0)
   {
      //Number of EAPOL frames of any type that have been transmitted by this
      //authenticator
      value->counter32 = port->stats.eapolFramesTx;
   }
   //dot1xAuthEapolStartFramesRx object?
   else if(osStrcmp(object->name, "dot1xAuthEapolStartFramesRx") == 0)
   {
      //Number of EAPOL Start frames that have been received by this
      //authenticator
      value->counter32 = port->stats.eapolStartFramesRx;
   }
   //dot1xAuthEapolLogoffFramesRx object?
   else if(osStrcmp(object->name, "dot1xAuthEapolLogoffFramesRx") == 0)
   {
      //Number of EAPOL Logoff frames that have been received by this
      //authenticator
      value->counter32 = port->stats.eapolLogoffFramesRx;
   }
   //dot1xAuthEapolRespIdFramesRx object?
   else if(osStrcmp(object->name, "dot1xAuthEapolRespIdFramesRx") == 0)
   {
      //Number of EAP Resp/Id frames that have been received by this
      //authenticator
      value->counter32 = port->stats.eapolRespIdFramesRx;
   }
   //dot1xAuthEapolRespFramesRx object?
   else if(osStrcmp(object->name, "dot1xAuthEapolRespFramesRx") == 0)
   {
      //Number of valid EAP Response frames (other than Resp/Id frames) that
      //have been received by this authenticator
      value->counter32 = port->stats.eapolRespFramesRx;
   }
   //dot1xAuthEapolReqIdFramesTx object?
   else if(osStrcmp(object->name, "dot1xAuthEapolReqIdFramesTx") == 0)
   {
      //Number of EAP Req/Id frames that have been transmitted by this
      //authenticator
      value->counter32 = port->stats.eapolReqIdFramesTx;
   }
   //dot1xAuthEapolReqFramesTx object?
   else if(osStrcmp(object->name, "dot1xAuthEapolReqFramesTx") == 0)
   {
      //Number of EAP Request frames (other than Rq/Id frames) that have been
      //transmitted by this authenticator
      value->counter32 = port->stats.eapolReqFramesTx;
   }
   //dot1xAuthInvalidEapolFramesRx object?
   else if(osStrcmp(object->name, "dot1xAuthInvalidEapolFramesRx") == 0)
   {
      //Number of EAPOL frames that have been received by this authenticator
      //in which the frame type is not recognized
      value->counter32 = port->stats.invalidEapolFramesRx;
   }
   //dot1xAuthEapLengthErrorFramesRx object?
   else if(osStrcmp(object->name, "dot1xAuthEapLengthErrorFramesRx") == 0)
   {
      //Number of EAPOL frames that have been received by this authenticator
      //in which the Packet Body Length field is invalid
      value->counter32 = port->stats.eapLengthErrorFramesRx;
   }
   //dot1xAuthLastEapolFrameVersion object?
   else if(osStrcmp(object->name, "dot1xAuthLastEapolFrameVersion") == 0)
   {
      //Protocol version number carried in the most recently received EAPOL
      //frame
      value->unsigned32 = port->stats.lastEapolFrameVersion;
   }
   //dot1xAuthLastEapolFrameSource object?
   else if(osStrcmp(object->name, "dot1xAuthLastEapolFrameSource") == 0)
   {
      //This object contains the source MAC address carried in the most
      //recently received EAPOL frame
      if(*valueLen >= sizeof(MacAddr))
      {
         //Copy object value
         macCopyAddr(value->octetString, &port->supplicantMacAddr);
         //Return object length
         *valueLen = sizeof(MacAddr);
      }
      else
      {
         //Report an error
         error = ERROR_BUFFER_OVERFLOW;
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
}


/**
 * @brief Get next dot1xAuthStatsEntry object
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] nextOid OID of the next object in the MIB
 * @param[out] nextOidLen Length of the next object identifier, in bytes
 * @return Error code
 **/

error_t ieee8021PaeMibGetNextDot1xAuthStatsEntry(const MibObject *object, const uint8_t *oid,
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


/**
 * @brief Get dot1xAuthSessionStatsEntry object value
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier (object name and instance identifier)
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] value Object value
 * @param[in,out] valueLen Length of the object value, in bytes
 * @return Error code
 **/

error_t ieee8021PaeMibGetDot1xAuthSessionStatsEntry(const MibObject *object, const uint8_t *oid,
   size_t oidLen, MibVariant *value, size_t *valueLen)
{
   error_t error;
   size_t n;
   uint_t dot1xPaePortNumber;
   AuthenticatorContext *context;
   AuthenticatorPort *port;

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

   //Point to the 802.1X authenticator context
   context = (AuthenticatorContext *) ieee8021PaeMibBase.authContext;
   //Sanity check
   if(context == NULL)
   {
      return ERROR_INSTANCE_NOT_FOUND;
   }

   //Invalid port index?
   if(dot1xPaePortNumber < 1 || dot1xPaePortNumber > context->numPorts)
   {
      return ERROR_INSTANCE_NOT_FOUND;
   }

   //Point to the port that matches the specified port index
   port = &context->ports[dot1xPaePortNumber - 1];

   //dot1xAuthSessionOctetsRx object?
   if(osStrcmp(object->name, "dot1xAuthSessionOctetsRx") == 0)
   {
      //Number of octets received in user data frames on this port during the
      //session
      value->counter64 = port->sessionStats.sessionOctetsRx;
   }
   //dot1xAuthSessionOctetsTx object?
   else if(osStrcmp(object->name, "dot1xAuthSessionOctetsTx") == 0)
   {
      //Number of octets transmitted in user data frames on this port during
      //the session
      value->counter64 = port->sessionStats.sessionOctetsTx;
   }
   //dot1xAuthSessionFramesRx object?
   else if(osStrcmp(object->name, "dot1xAuthSessionFramesRx") == 0)
   {
      //Number of user data frames received on this port during the session
      value->counter32 = port->sessionStats.sessionFramesRx;
   }
   //dot1xAuthSessionFramesTx object?
   else if(osStrcmp(object->name, "dot1xAuthSessionFramesTx") == 0)
   {
      //Number of user data frames transmitted on this port during the session
      value->counter32 = port->sessionStats.sessionFramesTx;
   }
   //dot1xAuthSessionId object?
   else if(osStrcmp(object->name, "dot1xAuthSessionId") == 0)
   {
      //A unique identifier for the session, in the form of a printable ASCII
      //string of at least three characters
      *valueLen = 0;
   }
   //dot1xAuthSessionAuthenticMethod object?
   else if(osStrcmp(object->name, "dot1xAuthSessionAuthenticMethod") == 0)
   {
      //Authentication method used to establish the session
      value->integer = IEEE8021_PAE_MIB_AUTH_METHOD_REMOTE_AUTH_SERVER;
   }
   //dot1xAuthSessionTime object?
   else if(osStrcmp(object->name, "dot1xAuthSessionTime") == 0)
   {
      //Duration of the session in seconds
      value->timeTicks = port->sessionStats.sessionTime * 100;
   }
   //dot1xAuthSessionTerminateCause object?
   else if(osStrcmp(object->name, "dot1xAuthSessionTerminateCause") == 0)
   {
      //Reason for the session termination
      switch(port->sessionStats.sessionTerminateCause)
      {
      case AUTHENTICATOR_TERMINATE_CAUSE_SUPPLICANT_LOGOFF:
         value->integer = IEEE8021_PAE_MIB_TERMINATE_CAUSE_SUPPLICANT_LOGOFF;
         break;
      case AUTHENTICATOR_TERMINATE_CAUSE_PORT_FAILURE:
         value->integer = IEEE8021_PAE_MIB_TERMINATE_CAUSE_PORT_FAILURE;
         break;
      case AUTHENTICATOR_TERMINATE_CAUSE_SUPPLICANT_RESTART:
         value->integer = IEEE8021_PAE_MIB_TERMINATE_CAUSE_SUPPLICANT_RESTART;
         break;
      case AUTHENTICATOR_TERMINATE_CAUSE_REAUTH_FAILED:
         value->integer = IEEE8021_PAE_MIB_TERMINATE_CAUSE_REAUTH_FAILED;
         break;
      case AUTHENTICATOR_TERMINATE_CAUSE_AUTH_CONTROL_FORCE_UNAUTH:
         value->integer = IEEE8021_PAE_MIB_TERMINATE_CAUSE_AUTH_CONTROL_FORCE_UNAUTH;
         break;
      case AUTHENTICATOR_TERMINATE_CAUSE_PORT_REINIT:
         value->integer = IEEE8021_PAE_MIB_TERMINATE_CAUSE_PORT_REINIT;
         break;
      case AUTHENTICATOR_TERMINATE_CAUSE_PORT_ADMIN_DISABLED:
         value->integer = IEEE8021_PAE_MIB_TERMINATE_CAUSE_PORT_ADMIN_DISABLED;
         break;
      case AUTHENTICATOR_TERMINATE_CAUSE_NOT_TERMINATED_YET:
         value->integer = IEEE8021_PAE_MIB_TERMINATE_CAUSE_NOT_TERMINATED_YET;
         break;
      default:
         value->integer = 0;
         break;
      }
   }
   //dot1xAuthSessionUserName object?
   else if(osStrcmp(object->name, "dot1xAuthSessionUserName") == 0)
   {
      //Retrieve the length of the user name
      n = osStrlen(port->aaaIdentity);

      //Make sure the buffer is large enough to hold the entire object
      if(*valueLen >= n)
      {
         //Copy object value
         osMemcpy(value->octetString, port->aaaIdentity, n);
         //Return object length
         *valueLen = n;
      }
      else
      {
         //Report an error
         error = ERROR_BUFFER_OVERFLOW;
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
}


/**
 * @brief Get next dot1xAuthSessionStatsEntry object
 * @param[in] object Pointer to the MIB object descriptor
 * @param[in] oid Object identifier
 * @param[in] oidLen Length of the OID, in bytes
 * @param[out] nextOid OID of the next object in the MIB
 * @param[out] nextOidLen Length of the next object identifier, in bytes
 * @return Error code
 **/

error_t ieee8021PaeMibGetNextDot1xAuthSessionStatsEntry(const MibObject *object, const uint8_t *oid,
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
