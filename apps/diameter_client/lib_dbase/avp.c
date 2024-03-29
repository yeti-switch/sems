/*
 * Copyright (C) 2002-2003 FhG Fokus
 *
 * This file is part of disc, a free diameter server/client.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program; if not, write to the Free Software 
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>


#include "log.h"
#include "diameter_msg.h"
#include "avp.h"

/*
 * each AVP type has some default set/reset flags and a proper data type.
 * All this default values (for flags and data-type) are correct/set by this
 * function.
 */
inline void set_avp_fields( AAA_AVPCode code, AAA_AVP *avp)
{
  switch (code) {
  case   1: /*AVP_User_Name*/
  case  25: /*AVP_Class*/
  case 263: /*AVP_Session_Id*/
  case 283: /*AVP_Destination_Realm*/
  case 293: /*AVP Destination Host*/
  case 264: /*AVP_Origin_Host*/
  case 296: /*AVP Origin_Realm*/
  case 400: /* AVP_Resource */	
  case 401: /* AVP_Response */	
  case 402: /* AVP_Chalenge */	
  case 403: /* AVP_Method */
  case 404: /* Service_Type AVP */
  case 405: /* User_Group AVP*/
    avp->flags = 0x40|(0x20&avp->flags);
    avp->type = AAA_AVP_STRING_TYPE;
    break;
  case  27: /*AVP_Session_Timeout*/
  case 258: /*AVP_Auth_Aplication_Id*/
  case 262: /*AVP_Redirect_Max_Cache_Time*/
  case 265: /*AVP_Supported_Vendor_Id*/
  case 266: /*AVP_Vendor_Id*/
  case 268: /*AVP_Result_Code*/
  case 270: /*AVP_Session_Binding*/
  case 276: /*AVP_Auth_Grace_Period*/
  case 278: /*AVP_Origin_State_Id*/
  case 291: /*AVP_Authorization_Lifetime*/
    avp->flags = 0x40|(0x20&avp->flags);
    avp->type = AAA_AVP_INTEGER32_TYPE;
    break;
  case 33: /*AVP_Proxy_State*/
    avp->flags = 0x40;
    avp->type = AAA_AVP_STRING_TYPE;
    break;
  case 257: /*AVP_Host_IP_Address*/
    avp->flags = 0x40|(0x20&avp->flags);
    avp->type = AAA_AVP_ADDRESS_TYPE;
    break;
  case 269: /*AVP_Product_Name*/
    avp->flags = 0x00;
    avp->type = AAA_AVP_STRING_TYPE;
    break;
  case 281: /*AVP_Error_Message*/
    avp->flags = (0x20&avp->flags);
    avp->type = AAA_AVP_STRING_TYPE;
    break;
  default:
    avp->type = AAA_AVP_DATA_TYPE;
  };
}

AAA_AVP* AAAAddGroupedAVP(AAA_AVP* grouped, AAA_AVP* avp) {
  AAA_AVP *mem;

  if (grouped == NULL || avp == NULL) {
    ERROR("trying to group NULL avp");
    return grouped;
  }
  // insert at head
  avp->next = grouped->groupedHead;
  grouped->groupedHead = avp;
  
  // recompute total length
  grouped->data.len = 0;
  for(mem=grouped->groupedHead;mem;mem=mem->next) {
    grouped->data.len += AVP_HDR_SIZE(mem->flags) + 
      to_32x_len( mem->data.len );
  }

  return grouped;
}

/* This function creates an AVP and returns a pointer to it;
 */
AAA_AVP*  AAACreateAVP(
		       AAA_AVPCode code,
		       AAA_AVPFlag flags,
		       AAAVendorId vendorId,
		       const char   *data,
		       unsigned int length,
		       AVPDataStatus data_status)
{
  AAA_AVP *avp;

  /* first check the params */
  if(( data==0 || length==0)  && 
     (( data_status==AVP_DUPLICATE_DATA )||
      ( data_status==AVP_FREE_DATA ))){
    ERROR("ERROR:AAACreateAVP: NULL value received for"
	  " param data/length !!\n");
    return 0;
  }

  /* allocated a new AVP struct */
  avp = 0;
  avp = (AAA_AVP*)ad_malloc(sizeof(AAA_AVP));
  if (!avp)
    goto error;
  memset( avp, 0, sizeof(AAA_AVP) );

  /* set some fields */
  //avp->free_it = free_it;
  avp->packetType = AAA_DIAMETER;
  avp->code=code;
  avp->flags=flags;
  avp->vendorId=vendorId;
  set_avp_fields( code, avp);

  if ( data_status==AVP_DUPLICATE_DATA ) {
    /* make a duplicate for data */
    avp->data.len = length;
    avp->data.s = (void*)ad_malloc(length);
    if(!avp->data.s)
      goto error;
    memcpy( avp->data.s, data, length);
    avp->free_it = 1;
  } else {
    avp->data.s = (char*)data;
    avp->data.len = length;
    avp->free_it = (data_status==AVP_FREE_DATA)?1:0;
  }

  return avp;
 error:
  ERROR("ERROR:AAACreateAVP: no more free memory!");
  return 0;
}



/* Insert the AVP avp into this avpList of a message after position */
AAAReturnCode  AAAAddAVPToMessage(
				  AAAMessage *msg,
				  AAA_AVP *avp,
				  AAA_AVP *position)
{
  AAA_AVP *avp_t;

  if ( !msg || !avp ) {
    ERROR("ERROR:AAAAddAVPToList: param msg or avp passed null"
	  " or *avpList=NULL and position!=NULL !!\n");
    return AAA_ERR_PARAMETER;
  }

  if (!position) {
    /* insert at the beginning */
    avp->next = msg->avpList.head;
    avp->prev = 0;
    msg->avpList.head = avp;
    if (avp->next)
      avp->next->prev = avp;
    else
      msg->avpList.tail = avp;
  } else {
    /* look after avp from position */
    for(avp_t=msg->avpList.head;avp_t&&avp_t!=position;avp_t=avp_t->next);
    if (!avp_t) {
      ERROR("ERROR: AAACreateAVP: the \"position\" avp is not in"
	    "\"msg\" message!!\n");
      return AAA_ERR_PARAMETER;
    }
    /* insert after position */
    avp->next = position->next;
    position->next = avp;
    if (avp->next)
      avp->next->prev = avp;
    else
      msg->avpList.tail = avp;
    avp->prev = position;
  }

  /* update the short-cuts */
  switch (avp->code) {
  case AVP_Session_Id: msg->sessionId = avp;break;
  case AVP_Origin_Host: msg->orig_host = avp;break;
  case AVP_Origin_Realm: msg->orig_realm = avp;break;
  case AVP_Destination_Host: msg->dest_host = avp;break;
  case AVP_Destination_Realm: msg->dest_realm = avp;break;
  case AVP_Result_Code: msg->res_code = avp;break;
  case AVP_Auth_Session_State: msg->auth_ses_state = avp;break;
  }

  return AAA_ERR_SUCCESS;
}

/* This function finds an AVP with matching code and vendor id */
AAA_AVP  *AAAFindMatchingAVP(
			     AAAMessage *msg,
			     AAA_AVP *startAvp,
			     AAA_AVPCode avpCode,
			     AAAVendorId vendorId,
			     AAASearchType searchType)
{
  AAA_AVP *avp_t;

  /* param checking */
  if (!msg) {
    ERROR("ERROR:FindMatchingAVP: param msg passed null !!");
    goto error;
  }
  /* search the startAVP avp */
  for(avp_t=msg->avpList.head;avp_t&&avp_t!=startAvp;avp_t=avp_t->next);
  if (!avp_t && startAvp) {
    ERROR("ERROR: AAAFindMatchingAVP: the \"position\" avp is not in"
	  "\"avpList\" list!!\n");
    goto error;
  }

  /* where should I start searching from ? */
  if (!startAvp)
    avp_t=(searchType==AAA_FORWARD_SEARCH)?(msg->avpList.head):
      (msg->avpList.tail);
  else
    avp_t=startAvp;

  /* start searching */
  while(avp_t) {
    if (avp_t->code==avpCode && avp_t->vendorId==vendorId)
      return avp_t;
    avp_t = (searchType==AAA_FORWARD_SEARCH)?(avp_t->next):(avp_t->prev);
  }

 error:
  return 0;
}


/* This function removes an AVP from a list of a message */
AAAReturnCode  AAARemoveAVPFromMessage(
				       AAAMessage *msg,
				       AAA_AVP *avp)
{
  AAA_AVP *avp_t;

  /* param check */
  if ( !msg || !avp ) {
    ERROR("ERROR:AAAAddAVPToList: param AVP_LIST \"avpList\" or AVP "
	  "\"avp\" passed null !!\n");
    return AAA_ERR_PARAMETER;
  }

  /* search the "avp" avp */
  for(avp_t=msg->avpList.head;avp_t&&avp_t!=avp;avp_t=avp_t->next);
  if (!avp_t) {
    ERROR("ERROR: AAACreateAVP: the \"avp\" avp is not in "
	  "\"avpList\" avp list!!\n");
    return AAA_ERR_PARAMETER;
  }

  /* remove the avp from list */
  if (msg->avpList.head==avp)
    msg->avpList.head = avp->next;
  else
    avp->prev->next = avp->next;
  if (avp->next)
    avp->next->prev = avp->prev;
  else
    msg->avpList.tail = avp->prev;
  avp->next = avp->prev = 0;

  /* update short-cuts */
  switch (avp->code) {
  case AVP_Session_Id: msg->sessionId = 0;break;
  case AVP_Origin_Host: msg->orig_host = 0;break;
  case AVP_Origin_Realm: msg->orig_realm = 0;break;
  case AVP_Destination_Host: msg->dest_host = 0;break;
  case AVP_Destination_Realm: msg->dest_realm = 0;break;
  case AVP_Result_Code: msg->res_code = 0;break;
  case AVP_Auth_Session_State: msg->auth_ses_state = 0;break;
  }

  return AAA_ERR_SUCCESS;
}



/* The function frees an AVP */
AAAReturnCode  AAAFreeAVP(AAA_AVP **avp)
{
  AAA_AVP *member_it;
  AAA_AVP *d_it;

  /* some checks */
  if (!avp || !(*avp)) {
    ERROR("ERROR:AAAFreeAVP: param avp cannot be null!!");
    return AAA_ERR_PARAMETER;
  }

  /* free all the mem */
  if ( (*avp)->free_it && (*avp)->data.s )
    ad_free((*avp)->data.s);
  
  /* free group members if any */
  member_it = (*avp)->groupedHead;
  while (member_it != NULL) {
    d_it = member_it;
    member_it = AAAGetNextAVP(member_it);
    AAAFreeAVP(&d_it);
  }

  ad_free( *avp );
  *avp = 0;

  return AAA_ERR_SUCCESS;
}



/* This function returns a pointer to the first AVP in the list */
AAA_AVP*  AAAGetFirstAVP(AAA_AVP_LIST *avpList){
  return avpList->head;
}

/* This function returns a pointer to the last AVP in the list */
AAA_AVP*  AAAGetLastAVP(AAA_AVP_LIST *avpList)
{
  return avpList->tail;
}

/* This function returns a pointer to the next AVP in the list */
AAA_AVP*  AAAGetNextAVP(AAA_AVP *avp)
{
  return avp->next;
}

/* This function returns a pointer to the previous AVP in the list */
AAA_AVP*  AAAGetPrevAVP(AAA_AVP *avp)
{
  return avp->prev;
}


/* This function converts the data in the AVP to a format suitable for
 * log or display functions. */
char*  AAAConvertAVPToString(AAA_AVP *avp, char *dest, unsigned int destLen)
{
  int l;
  int i;
  AAA_AVP *it;

  if (!avp || !dest || !destLen) {
    ERROR("ERROR:AAAConvertAVPToString: param AVP, DEST or DESTLEN "
	  "passed as null!!!\n");
    return 0;
  }
  l = snprintf(dest,destLen,"AVP(%p < %p >%p):packetType=%u;code=%u,"
	       "flags=%x;\nDataType=%u;VendorID=%u;DataLen=%u;\n",
	       avp->prev,avp,avp->next,avp->packetType,avp->code,avp->flags,
	       avp->type,avp->vendorId,avp->data.len);
  if ((it = avp->groupedHead)) {
    l+=snprintf(dest+l,destLen-l, "Group members:\n---\n");
    while (it) {
      DBG("print...");
      l+=strlen(AAAConvertAVPToString(it, dest+l, destLen-l));
      l+=snprintf(dest+l,destLen-l, "\n---\n");
      it = AAAGetNextAVP(it);
    }
  } else {

    switch(avp->type) {
    case AAA_AVP_STRING_TYPE:
      /*l+=*/snprintf(dest+l,destLen-l,"String: <%.*s>",avp->data.len,
		  avp->data.s);
      break;
    case AAA_AVP_INTEGER32_TYPE:
      /*l+=*/snprintf(dest+l,destLen-l,"Int32: <%u>(%x)",
		  (unsigned int)htonl(*((unsigned int*)avp->data.s)),
		  (unsigned int)htonl(*((unsigned int*)avp->data.s)));
      break;
    case AAA_AVP_ADDRESS_TYPE:
      i = 1;
      switch (avp->data.len) {
      case 4: i=i*0;
      case 6: i=i*2;
	/*l+=*/snprintf(dest+l,destLen-l,"Address IPv4: <%d.%d.%d.%d>",
		    (unsigned char)avp->data.s[i+0],
		    (unsigned char)avp->data.s[i+1],
		    (unsigned char)avp->data.s[i+2],
		    (unsigned char)avp->data.s[i+3]);
	break;
      case 16: i=i*0;
      case 18: i=i*2;
	/*l+=*/snprintf(dest+l,destLen-l,
		    "Address IPv6: <%x.%x.%x.%x.%x.%x.%x.%x>",
		    ((avp->data.s[i+0]<<8)+avp->data.s[i+1]),
		    ((avp->data.s[i+2]<<8)+avp->data.s[i+3]),
		    ((avp->data.s[i+4]<<8)+avp->data.s[i+5]),
		    ((avp->data.s[i+6]<<8)+avp->data.s[i+7]),
		    ((avp->data.s[i+8]<<8)+avp->data.s[i+9]),
		    ((avp->data.s[i+10]<<8)+avp->data.s[i+11]),
		    ((avp->data.s[i+12]<<8)+avp->data.s[i+13]),
		    ((avp->data.s[i+14]<<8)+avp->data.s[i+15]));
	break;
	break;
      }
      break;
      //case AAA_AVP_INTEGER64_TYPE:
    case AAA_AVP_TIME_TYPE:
    default:
      WARN("WARNING:AAAConvertAVPToString: don't know how to print"
	   " this data type [%d] -> tryng hexa\n",avp->type);
    case AAA_AVP_DATA_TYPE:
      for (i=0;i<avp->data.len&&l<destLen-1;i++)
	l+=snprintf(dest+l,destLen-l-1,"%x",
		    ((unsigned char*)avp->data.s)[i]);
    }
  }
  return dest;
}

/* todo: support clone for grouped AVPs*/
AAA_AVP* AAACloneAVP( AAA_AVP *avp , unsigned char clone_data)
{
  AAA_AVP *n_avp;

  if (!avp || !(avp->data.s) || !(avp->data.len) )
    goto error;

  /* clone the avp structure */
  n_avp = (AAA_AVP*)ad_malloc( sizeof(AAA_AVP) );
  if (!n_avp) {
    ERROR("ERROR:clone_avp: cannot get free memory!!");
    goto error;
  }
  memcpy( n_avp, avp, sizeof(AAA_AVP));
  n_avp->next = n_avp->prev = 0;

  if (clone_data) {
    /* clone the avp data */
    n_avp->data.s = (char*)ad_malloc( avp->data.len );
    if (!(n_avp->data.s)) {
      ERROR("ERROR:clone_avp: cannot get free memory!!");
      ad_free( n_avp );
      goto error;
    }
    memcpy( n_avp->data.s, avp->data.s, avp->data.len);
    n_avp->free_it = 1;
  } else {
    /* link the clone's data to the original's data */
    n_avp->data.s = avp->data.s;
    n_avp->data.len = avp->data.len;
    n_avp->free_it = 0;
  }

  return n_avp;
 error:
  return 0;
}


