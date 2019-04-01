#include "AmISUP.h"

#include <sstream>
#include <iomanip>

#define DUMP_ON_PARSING 1

static void dump_buffer(const char *prefix, char *buf,size_t len)
{
	std::stringstream s;
	size_t i = 0,j;
	int hex;

	s << std::setfill('0');

	while(i < len){
		s << "0x" << std::setw(4) << std::hex << i << ": ";
		for(j = 0;i < len && j<0x10; i++,j++){
			hex = buf[i]&0xff;
			s << "0x" << std::setw(2) << hex << " ";
		}
		s << std::endl;
	}

	DBG("%s:\n%s",
		prefix,s.str().c_str());
}

static const char *proto_type_get_str(AmISUP::isup_proto_type proto){
	switch(proto){
	case AmISUP::SS7_ITU:
		return "ITU"; break;
	case AmISUP::SS7_ANSI:
		return "ANSI"; break;
	case AmISUP::SS7_UNKNOWN:
	default:
		return "Unknown"; break;
	}
}

enum isup_parm_type {
	PARM_TYPE_FIXED  = 1,
	PARM_TYPE_VARIABLE,
	PARM_TYPE_OPTIONAL
};

/* ISUP Parameter Pseudo-type */
struct isup_parm_opt {
	unsigned char type;
	unsigned char len;
	unsigned char data[0];
};

struct isup_h {
	//unsigned char cic[2];
	unsigned char type;
	unsigned char data[0]; /* This is the contents of the message */
};

/* ISUP messages */
#define ISUP_UNDEF	0x00
#define ISUP_IAM	0x01
#define ISUP_SAM	0x02
#define ISUP_INR	0x03
#define ISUP_INF	0x04
#define ISUP_COT	0x05
#define ISUP_ACM	0x06
#define ISUP_CON	0x07
#define ISUP_FOT	0x08
#define ISUP_ANM	0x09
#define ISUP_REL	0x0c
#define ISUP_SUS	0x0d
#define ISUP_RES	0x0e
#define ISUP_RLC	0x10
#define ISUP_CCR	0x11
#define ISUP_RSC	0x12
#define ISUP_BLO	0x13
#define ISUP_UBL	0x14
#define ISUP_BLA	0x15
#define ISUP_UBA	0x16
#define ISUP_GRS	0x17
#define ISUP_CGB	0x18
#define ISUP_CGU	0x19
#define ISUP_CGBA	0x1a
#define ISUP_CGUA	0x1b
#define ISUP_CMR	0x1c
#define ISUP_CMC	0x1d
#define ISUP_CMRJ	0x1e
#define ISUP_FAR	0x1f
#define ISUP_FAA	0x20
#define ISUP_FRJ	0x21
#define ISUP_FAD	0x22
#define ISUP_FAI	0x23
#define ISUP_LPA	0x24
#define ISUP_CSVR	0x25
#define ISUP_CSVS	0x26
#define ISUP_DRS	0x27
#define ISUP_PAM	0x28
#define ISUP_GRA	0x29
#define ISUP_CQM	0x2a
#define ISUP_CQR	0x2b
#define ISUP_CPG	0x2c
#define ISUP_USR	0x2d
#define ISUP_UCIC	0x2e
#define ISUP_CFN	0x2f
#define ISUP_OLM	0x30
#define ISUP_CRG	0x31
#define ISUP_FAC	0x33
#define ISUP_CRA	0xe9
#define ISUP_CRM	0xea
#define ISUP_CVR	0xeb
#define ISUP_CVT	0xec
#define ISUP_EXM	0xed

/* ISUP Parameters */
#define ISUP_PARM_NATURE_OF_CONNECTION_IND 0x06
#define ISUP_PARM_FORWARD_CALL_IND 0x07
#define ISUP_PARM_CALLING_PARTY_CAT 0x09
#define ISUP_PARM_USER_SERVICE_INFO 0x1d
#define ISUP_PARM_TRANSMISSION_MEDIUM_REQS 0x02
#define ISUP_PARM_CALLED_PARTY_NUM 0x04
#define ISUP_PARM_ACCESS_TRANS 0x03
#define ISUP_PARM_BUSINESS_GRP 0xc6
#define ISUP_PARM_CALL_REF 0x01
#define ISUP_PARM_CALLING_PARTY_NUM 0x0a
#define ISUP_PARM_CARRIER_ID 0xc5
#define ISUP_PARM_SELECTION_INFO 0xee
#define ISUP_PARM_CHARGE_NUMBER 0xeb
#define ISUP_PARM_CIRCUIT_ASSIGNMENT_MAP 0x25
#define ISUP_PARM_OPT_BACKWARD_CALL_IND 0x29
#define ISUP_PARM_CONNECTION_REQ 0x0d
#define ISUP_PARM_CONTINUITY_IND 0x10
#define ISUP_PARM_CUG_INTERLOCK_CODE 0x1c
#define ISUP_PARM_EGRESS_SERV 0xc3
#define ISUP_PARM_GENERIC_ADDR 0xc0
#define ISUP_PARM_GENERIC_DIGITS 0xc1
#define ISUP_PARM_GENERIC_NAME 0xc7
#define ISUP_PARM_GENERIC_NOTIFICATION_IND 0x2c
#define ISUP_PARM_BACKWARD_CALL_IND 0x11
#define ISUP_PARM_CAUSE 0x12
#define ISUP_PARM_CIRCUIT_GROUP_SUPERVISION_IND 0x15
#define ISUP_PARM_RANGE_AND_STATUS 0x16
#define ISUP_PARM_PROPAGATION_DELAY 0x31
#define ISUP_PARM_EVENT_INFO 0x24
#define ISUP_PARM_HOP_COUNTER 0x3d
#define ISUP_PARM_OPT_FORWARD_CALL_INDICATOR 0x08
#define ISUP_PARM_LOCATION_NUMBER 0x3f
#define ISUP_PARM_ORIG_LINE_INFO 0xea
#define ISUP_PARM_REDIRECTION_INFO 0x13
#define ISUP_PARM_ORIGINAL_CALLED_NUM 0x28
#define ISUP_PARM_JIP 0xc4
#define ISUP_PARM_ECHO_CONTROL_INFO 0x37
#define ISUP_PARM_PARAMETER_COMPAT_INFO 0x39
#define ISUP_PARM_CIRCUIT_STATE_IND 0x26
#define ISUP_PARM_TRANSIT_NETWORK_SELECTION 0x23
#define ISUP_PARM_LOCAL_SERVICE_PROVIDER_IDENTIFICATION 0xe4
#define ISUP_PARM_FACILITY_IND 0x18
#define ISUP_PARM_REDIRECTING_NUMBER 0x0b
#define ISUP_PARM_ACCESS_DELIVERY_INFO 0x2e

#define CODE_CCITT 0x0

#define LOC_PRIV_NET_LOCAL_USER 0x1

static int iam_params[] = {ISUP_PARM_NATURE_OF_CONNECTION_IND, ISUP_PARM_FORWARD_CALL_IND, ISUP_PARM_CALLING_PARTY_CAT,
	ISUP_PARM_TRANSMISSION_MEDIUM_REQS, ISUP_PARM_CALLED_PARTY_NUM, ISUP_PARM_CALLING_PARTY_NUM, -1};

static int ansi_iam_params[] = {ISUP_PARM_NATURE_OF_CONNECTION_IND, ISUP_PARM_FORWARD_CALL_IND, ISUP_PARM_CALLING_PARTY_CAT,
	ISUP_PARM_USER_SERVICE_INFO, ISUP_PARM_CALLED_PARTY_NUM, ISUP_PARM_CALLING_PARTY_NUM, ISUP_PARM_CHARGE_NUMBER,
	ISUP_PARM_ORIG_LINE_INFO, ISUP_PARM_GENERIC_ADDR, ISUP_PARM_GENERIC_DIGITS, ISUP_PARM_GENERIC_NAME, ISUP_PARM_JIP,
	ISUP_PARM_LOCAL_SERVICE_PROVIDER_IDENTIFICATION, -1};


static int acm_params[] = {ISUP_PARM_BACKWARD_CALL_IND, -1};

static int faa_params[] = {ISUP_PARM_FACILITY_IND, ISUP_PARM_CALL_REF, -1};

static int far_params[] = {ISUP_PARM_FACILITY_IND, ISUP_PARM_CALL_REF, -1};

static int anm_params[] = { -1};

static int con_params[] = { ISUP_PARM_BACKWARD_CALL_IND, -1};

static int rel_params[] = { ISUP_PARM_CAUSE, -1};

static int greset_params[] = { ISUP_PARM_RANGE_AND_STATUS, -1};

static int cot_params[] = { ISUP_PARM_CONTINUITY_IND, -1};

static int cpg_params[] = { ISUP_PARM_EVENT_INFO, -1};

static int cicgroup_params[] = { ISUP_PARM_CIRCUIT_GROUP_SUPERVISION_IND, ISUP_PARM_RANGE_AND_STATUS, -1};

static int cqr_params[] = { ISUP_PARM_RANGE_AND_STATUS, ISUP_PARM_CIRCUIT_STATE_IND, -1};

static int empty_params[] = { -1};

static struct message_data {
	int messagetype;
	int mand_fixed_params;
	int mand_var_params;
	int opt_params;
	int *param_list;
} messages[] = {
	{ISUP_IAM, 4, 1, 1, iam_params},
	{ISUP_ACM, 1, 0, 1, acm_params},
	{ISUP_ANM, 0, 0, 1, anm_params},
	{ISUP_CON, 1, 0, 1, con_params},
	{ISUP_REL, 0, 1, 1, rel_params},
	{ISUP_RLC, 0, 0, 1, empty_params},
	{ISUP_GRS, 0, 1, 0, greset_params},
	{ISUP_GRA, 0, 1, 0, greset_params},
	{ISUP_CGB, 1, 1, 0, cicgroup_params},
	{ISUP_CGU, 1, 1, 0, cicgroup_params},
	{ISUP_CGBA, 1, 1, 0, cicgroup_params},
	{ISUP_CGUA, 1, 1, 0, cicgroup_params},
	{ISUP_COT, 1, 0, 0, cot_params},
	{ISUP_CCR, 0, 0, 0, empty_params},
	{ISUP_BLO, 0, 0, 0, empty_params},
	{ISUP_LPA, 0, 0, 0, empty_params},
	{ISUP_UBL, 0, 0, 0, empty_params},
	{ISUP_BLA, 0, 0, 0, empty_params},
	{ISUP_UBA, 0, 0, 0, empty_params},
	{ISUP_RSC, 0, 0, 0, empty_params},
	{ISUP_CVR, 0, 0, 0, empty_params},
	{ISUP_CVT, 0, 0, 0, empty_params},
	{ISUP_CPG, 1, 0, 1, cpg_params},
	{ISUP_UCIC, 0, 0, 0, empty_params},
	{ISUP_CQM, 0, 1, 0, greset_params},
	{ISUP_CQR, 0, 2, 0, cqr_params},
	{ISUP_FAA, 1, 0, 1, faa_params},
	{ISUP_FAR, 1, 0, 1, far_params},
	{ISUP_CFN, 0, 1, 0, rel_params}
};

static const char * message2str(unsigned char message)
{
	switch (message) {
		case ISUP_UNDEF:
			return "UNDEFINED";
		case ISUP_IAM:
			return "IAM";
		case ISUP_ACM:
			return "ACM";
		case ISUP_ANM:
			return "ANM";
		case ISUP_REL:
			return "REL";
		case ISUP_RLC:
			return "RLC";
		case ISUP_GRS:
			return "GRS";
		case ISUP_GRA:
			return "GRA";
		case ISUP_COT:
			return "COT";
		case ISUP_CCR:
			return "CCR";
		case ISUP_BLO:
			return "BLO";
		case ISUP_UBL:
			return "UBL";
		case ISUP_BLA:
			return "BLA";
		case ISUP_UBA:
			return "UBA";
		case ISUP_CGB:
			return "CGB";
		case ISUP_CGU:
			return "CGU";
		case ISUP_CGBA:
			return "CGBA";
		case ISUP_CGUA:
			return "CGUA";
		case ISUP_RSC:
			return "RSC";
		case ISUP_CPG:
			return "CPG";
		case ISUP_UCIC:
			return "UCIC";
		case ISUP_LPA:
			return "LPA";
		case ISUP_FAA:
			return "FAA";
		case ISUP_FAR:
			return "FAR";
		case ISUP_FRJ:
			return "FRJ";
		case ISUP_CVT:
			return "CVT";
		case ISUP_CVR:
			return "CVR";
		case ISUP_CFN:
			return "CFN";
		default:
			return "Unknown";
	}
}

static char char2digit(char localchar)
{
	switch (localchar) {
		case '0':
			return 0;
		case '1':
			return 1;
		case '2':
			return 2;
		case '3':
			return 3;
		case '4':
			return 4;
		case '5':
			return 5;
		case '6':
			return 6;
		case '7':
			return 7;
		case '8':
			return 8;
		case '9':
			return 9;
		case '#':
			return 0xf;
		default:
			return 0;
	}
}

static char digit2char(unsigned char digit)
{
	switch (digit & 0xf) {
		case 0:
			return '0';
		case 1:
			return '1';
		case 2:
			return '2';
		case 3:
			return '3';
		case 4:
			return '4';
		case 5:
			return '5';
		case 6:
			return '6';
		case 7:
			return '7';
		case 8:
			return '8';
		case 9:
			return '9';
		case 15:
			return '#';
		default:
			return 0;
	}
}

static void isup_get_number(char *dest, unsigned char *src, int srclen, int oddeven)
{
	int i;

	if (oddeven < 2) {
		/* BCD odd or even */
		for (i = 0; i < ((srclen * 2) - oddeven); i++)
			dest[i] = digit2char(src[i/2] >> ((i % 2) ? 4 : 0));
	} else {
		/* oddeven = 2 for IA5 characters */
		for (i = 0; i < srclen; i++)
			dest[i] = src[i];
	}
	dest[i] = '\0';
}

/**
 * isup_get_number
 * @return true on finite number, false otherwise
 */
static bool isup_get_number(string &out, unsigned char *src, int srclen, int oddeven)
{
	int i;
	char dest[ISUP_MAX_NUM];

	if (oddeven < 2) {
		/* BCD odd or even */
		for (i = 0; i < ((srclen * 2) - oddeven); i++)
			dest[i] = digit2char(src[i/2] >> ((i % 2) ? 4 : 0));
	} else {
		/* oddeven = 2 for IA5 characters */
		for (i = 0; i < srclen; i++)
			dest[i] = src[i];
	}
	out = string(dest,i);
	return dest[i-1]=='#';
}

static void isup_put_generic(unsigned char *dest, string &src, int *len)
{
	int i = 0;
	int numlen = src.length();

	*len = numlen;

	while (i < numlen) {
		dest[i] = (src[i]);
		i++;
	}
}


static void isup_put_number(unsigned char *dest, string &src, int *len, int *oddeven)
{
	int i = 0;
	int numlen = src.length();

	if (numlen % 2) {
		*oddeven = 1;
		*len = numlen/2 + 1;
	} else {
		*oddeven = 0;
		*len = numlen/2;
	}

	while (i < numlen) {
		if (!(i % 2))
			dest[i/2] |= char2digit(src[i]) & 0xf;
		else
			dest[i/2] |= (char2digit(src[i]) << 4) & 0xf0;
		i++;
	}
}


#define FUNC_DUMP(name) int (name)(AmISUP *msg, int messagetype, unsigned char *parm, int len)
/* Length here is paramter length */
#define FUNC_RECV(name) int (name)(AmISUP *msg, int messagetype, unsigned char *parm, int len)
/* Length here is maximum length */
#define FUNC_SEND(name) int (name)(AmISUP *msg, int messagetype, unsigned char *parm, int len)


static FUNC_SEND(nature_of_connection_ind_transmit)
{
	parm[0] = 0x00;

	if (msg->cot_check_required)
		parm[0] |= 0x04;

	return 1; /* Length plus size of type header */
}

static FUNC_RECV(nature_of_connection_ind_receive)
{
	unsigned char cci = (parm[0] >> 2) & 0x3;

	if (cci == 0x1)
		msg->cot_check_required = 1;
	else
		msg->cot_check_required = 0;

	return 1;
}

static FUNC_DUMP(nature_of_connection_ind_dump)
{
	unsigned char con = parm[0];
	char *continuity;

	DBG("\tSatellites in connection: %d\n", con&0x03);
	con>>=2;
	switch (con & 0x03) {
		case 0:
			continuity = (char *)"Check not required";
			break;
		case 1:
			continuity = (char *)"Check required on this circuit";
			break;
		case 2:
			continuity = (char *)"Check performed on a previous circuit";
			break;
		case 3:
			continuity = (char *)"spare";
			break;
	}
	DBG("\tContinuity Check: %s (%d)\n", continuity, con & 0x3);
	con>>=2;
	con &= 0x01;

	DBG("\tOutgoing half echo control device: %s (%d)\n", con ? "included" : "not included", con);

	return 1;
}


static FUNC_SEND(forward_call_ind_transmit)
{
	parm[0] = 0x60;
	parm[1] = 0x01;
	return 2;
}

static FUNC_RECV(forward_call_ind_receive)
{
	return 2;
}

static FUNC_DUMP(forward_call_ind_dump)
{
	char *cb_str, *hg_str, *kj_str;
	switch ((parm[0] >> 1) & 3) {
		case 0:
			cb_str = (char *)"no end-to-end";
			break;
		case 1:
			cb_str = (char *)"pass-along";
			break;
		case 2:
			cb_str = (char *)"SCCP";
			break;
		case 3:
			cb_str = (char *)"pass-along and SCCP";
			break;
	}

	switch ((parm[0] >> 6) & 3) {
		case 0:
			hg_str = (char *)"ISDN user part preferred all the way";
			break;
		case 1:
			hg_str = (char *)"ISDN user part not preferred all the way";
			break;
		case 2:
			hg_str = (char *)"ISDN user part required all the way";
			break;
		case 3:
			hg_str = (char *)"spare";
			break;
	}

	switch ((parm[1] >> 1) & 3) {
		case 0:
			kj_str = (char *)"no indication";
			break;
		case 1:
			kj_str = (char *)"connectionless method available";
			break;
		case 2:
			kj_str = (char *)"connection oriented method available";
			break;
		case 3:
			kj_str = (char *)"connectionless and connection oriented method available";
			break;
	}

	DBG("\tNat/Intl Call Ind: call to be treated as a %s call (%d)\n", (parm[0] & 1) ? "international" : "national", parm[0] & 1);
	DBG("\tEnd to End Method Ind: %s method(s) available (%d)\n", cb_str, (parm[0] >> 1) & 3);
	DBG("\tInterworking Ind: %sinterworking encountered (%d)\n", ((parm[0] >> 3) & 1) ? "" : "no ", (parm[0] >> 3) & 1);
	DBG("\tEnd to End Info Ind: %send-to-end information available (%d)\n", ((parm[0]>>4)&1) ? "" : "no ", (parm[0] >> 4) & 1);
	DBG("\tISDN User Part Ind: ISDN user part %sused all the way (%d)\n", ((parm[0]>>5)&1) ? "" : "not ", (parm[0] >> 5) & 1);
	DBG("\tISDN User Part Pref Ind: %s (%d)\n", hg_str, (parm[0] >> 6) & 3);
	DBG("\tISDN Access Ind: originating access %s (%d)\n", (parm[1] & 1) ? "ISDN" : "non-ISDN", parm[1] & 1);
	DBG("\tSCCP Method Ind: %s (%d)\n", kj_str, (parm[1] >> 1) & 3);
	return 2;
}

static FUNC_RECV(calling_party_cat_receive)
{
	msg->calling_party_cat = parm[0];
	return 1;
}

static FUNC_SEND(calling_party_cat_transmit)
{
	parm[0] = 0x0a; /* Default to Ordinary calling subscriber */
	return 1;
}

static FUNC_DUMP(calling_party_cat_dump)
{
	char *cattype;

	switch (parm[0]) {
		case 1:
			cattype = (char *)"Operator, French";
			break;
		case 2:
			cattype = (char *)"Operator, English";
			break;
		case 3:
			cattype = (char *)"Operator, German";
			break;
		case 4:
			cattype = (char *)"Operator, Russian";
			break;
		case 5:
			cattype = (char *)"Operator, Spanish";
			break;
		case 9:
			cattype = (char *)"Reserved";
			break;
		case 10:
			cattype = (char *)"Ordinary calling subscriber";
			break;
		case 11:
			cattype = (char *)"Calling subscriber with priority";
			break;
		case 12:
			cattype = (char *)"Data Call (voice band data)";
			break;
		case 13:
			cattype = (char *)"Test Call";
			break;
		case 15:
			cattype = (char *)"Payphone";
			break;
		default:
			cattype = (char *)"Unknown";
			break;
	}

	DBG("\tCategory: %s (%d)\n", cattype, parm[0]);
	return 1;
}

static FUNC_RECV(user_service_info_receive)
{
	/* NoOp it for now */
	return len;
}

static FUNC_SEND(user_service_info_transmit)
{
	/* Default to Coding standard CCITT / 3.1 khz Audio */
	parm[0] = 0x90;
	/* Default to Circuit mode / 64kbps */
	parm[1] = 0x90;
	/* User Layer 1 set to ulaw */
	parm[2] = 0xa2;

	return 3;
}

static FUNC_SEND(transmission_medium_reqs_transmit)
{
	if (msg->proto_type != AmISUP::SS7_ITU)
		return 0;
	/* Speech */
	parm[0] = 0;
	return 1;
}

static FUNC_RECV(transmission_medium_reqs_receive)
{
	msg->transcap = parm[0] & 0x7f;
	return 1;
}

static FUNC_DUMP(transmission_medium_reqs_dump)
{
	char *type;

	switch (parm[0]) {
		case 0:
			type = (char *)"Speech";
			break;
		case 1:
			type = (char *)"Spare";
			break;
		case 2:
			type = (char *)"64 kbit/s unrestricted";
			break;
		case 4:
			type = (char *)"3.1 khz audio";
			break;
		case 6:
			type = (char *)"64 kbit/s preferred";
			break;
		case 7:
			type = (char *)"2 x 64 kbit/s unrestricted";
			break;
		case 8:
			type = (char *)"384 kbit/s unrestricted";
			break;
		case 9:
			type = (char *)"1536 kbit/s unrestricted";
			break;
		case 10:
			type = (char *)"1920 kbit/s unrestricted";
			break;
		default:
			type = (char *)"N x 64kbit/s unrestricted or possibly spare";
			break;
	}
	DBG("\t%s (%d)\n", type, parm[0]);
	return 1;
}

static FUNC_DUMP(called_party_num_dump)
{
	int oddeven = (parm[0] >> 7) & 0x1;
	char numbuf[64] = "";

	DBG("\tNature of address: %x\n", parm[0] & 0x7f);
	DBG("\tNI: %x\n", (parm[1] >> 7) & 0x1);
	DBG("\tNumbering plan: %x\n", (parm[1] >> 4) & 0x7);

	isup_get_number(numbuf, &parm[2], len - 2, oddeven);

	DBG("\tAddress signals: %s\n", numbuf);

	return len;
}

/* For variable length parameters we pass in the length of the parameter */
static FUNC_RECV(called_party_num_receive)
{
	int odd = 0;

	if (parm[0] & 0x80)
		odd = 1;

	msg->calling_party_num_finite = isup_get_number(msg->called_party_num, &parm[2], len - 2, odd);

	msg->called_nai = parm[0] & 0x7f; /* Nature of Address Indicator */

	return len;
}

static FUNC_SEND(called_party_num_transmit)
{
	int numlen, oddeven;

	isup_put_number(&parm[2], msg->called_party_num, &numlen, &oddeven);

	parm[0] = msg->called_nai & 0x7f; /* Nature of Address Indicator */

	if (oddeven)
		parm[0] |= 0x80; /* Odd number of digits */

	parm[1] = 0x1 << 4; /* Assume E.164 ISDN numbering plan, called number complete  */

	return numlen + 2;
}

static FUNC_RECV(backward_call_ind_receive)
{
	msg->called_party_status_ind = (parm[0] >> 2) & 0x3;
	return 2;
}

static FUNC_SEND(backward_call_ind_transmit)
{
	parm[0] = 0x40;
	parm[1] = 0x14;
	return 2;
}

static FUNC_DUMP(backward_call_ind_dump)
{
	unsigned char ba = parm[0] & 0x3;
	unsigned char dc = (parm[0] >> 2) & 0x3;
	unsigned char fe = (parm[0] >> 4) & 0x3;
	unsigned char hg = (parm[0] >> 6) & 0x3;
	unsigned char i = parm[1] & 0x1;
	unsigned char j = (parm[1] >> 1) & 0x1;
	unsigned char k = (parm[1] >> 2) & 0x1;
	unsigned char l = (parm[1] >> 3) & 0x1;
	unsigned char m = (parm[1] >> 4) & 0x1;
	unsigned char n = (parm[1] >> 5) & 0x1;
	unsigned char pq = (parm[1] >> 7) & 0x3;

	DBG("\tCharge indicator: %d\n", ba);
	DBG("\tCalled party's status indicator: %d\n", dc);
	DBG("\tCalled party's category indicator: %d\n", fe);
	DBG("\tEnd to End method indicator: %d\n", hg);
	DBG("\tInterworking indicator: %d\n", i);
	DBG("\tEnd to End information indicator: %d\n", j);
	DBG("\tISDN user part indicator: %d\n", k);
	DBG("\tHolding indicator: %d\n", l);
	DBG("\tISDN access indicator: %d\n", m);
	DBG("\tEcho control device indicator: %d\n", n);
	DBG("\tSCCP method indicator: %d\n", pq);

	return 2;
}

static FUNC_RECV(opt_backward_call_ind_receive)
{
	return 1;
}

static FUNC_DUMP(opt_backward_call_ind_dump)
{
	unsigned char a, b, c, d;
	a = parm[0] & 1;
	b = (parm[0] >> 1) & 1;
	c = (parm[0] >> 2) & 1;
	d = (parm[0] >> 3) & 1;

	DBG("\tIn-band information indicator: %d\n", a);
	DBG("\tCall diversion may occur indicator: %d\n", b);
	DBG("\tSimple segmentation indicator: %d\n", c);
	DBG("\tMLPP user indicator: %d\n", d);
	return 1;
}

static FUNC_RECV(cause_receive)
{
	msg->causeloc = parm[0] & 0xf;
	msg->causecode = (parm[0] & 0x60) >> 5;
	msg->cause = (parm[1] & 0x7f);

	return len;
}

static FUNC_SEND(cause_transmit)
{
	parm[0] = 0x80 | (msg->causecode << 5) | msg->causeloc;
	parm[1] = 0x80 | msg->cause;
	return 2;
}

static FUNC_DUMP(cause_dump)
{
	char *cause;
	switch (parm[1] & 0x7f) {
		case 1:
			cause = (char *)"Unallocated (unassigned) number";
			break;
		case 2:
			cause = (char *)"No route to specified transit network";
			break;
		case 3:
			cause = (char *)"No route to destination";
			break;
		case 4:
			cause = (char *)"Send special information tone";
			break;
		case 5:
			cause = (char *)"Misdialled trunk prefix";
			break;
		case 6:
			cause = (char *)"Channel unacceptable";
			break;
		case 7:
			cause = (char *)"Call awarded and being delivered in an established channel";
			break;
		case 8:
			cause = (char *)"Preemption";
			break;
		case 9:
			cause = (char *)"Preemption - circuit reserved for reuse";
			break;
		case 16:
			cause = (char *)"Normal call clearing";
			break;
		case 17:
			cause = (char *)"User busy";
			break;
		case 18:
			cause = (char *)"No user responding";
			break;
		case 19:
			cause = (char *)"No answer from user (user alerted)";
			break;
		case 20:
			cause = (char *)"Subscriber absent";
			break;
		case 21:
			cause = (char *)"Call rejected";
			break;
		case 22:
			cause = (char *)"Number changed";
			break;
		case 23:
			cause = (char *)"Redirection to new destination";
			break;
		case 25:
			cause = (char *)"Exchange routing error";
			break;
		case 26:
			cause = (char *)"Non-selected user clearing";
			break;
		case 27:
			cause = (char *)"Destination out of order";
			break;
		case 28:
			cause = (char *)"Invalid number format (address incomplete)";
			break;
		case 29:
			cause = (char *)"Facility rejected";
			break;
		case 30:
			cause = (char *)"Response to STATUS ENQUIRY";
			break;
		case 31:
			cause = (char *)"Normal, unspecified";
			break;
		case 34:
			cause = (char *)"No circuit/channel available";
			break;
		case 38:
			cause = (char *)"Network out of order";
			break;
		case 39:
			cause = (char *)"Permanent frame mode connection out of service";
			break;
		case 40:
			cause = (char *)"Permanent frame mode connection operational";
			break;
		case 41:
			cause = (char *)"Temporary failure";
			break;
		case 42:
			cause = (char *)"Switching equipment congestion";
			break;
/* TODO: Finish the rest of these */
		default:
			cause = (char *)"Unknown";
	}
	DBG("\tCoding Standard: %d\n", (parm[0] >> 5) & 3);
	DBG("\tLocation: %d\n", parm[0] & 0xf);
	DBG("\tCause Class: %d\n", (parm[1]>>4) & 0x7);
	DBG("\tCause Subclass: %d\n", parm[1] & 0xf);
	DBG("\tCause: %s (%d)\n", cause, parm[1] & 0x7f);

	return len;
}


static FUNC_DUMP(range_and_status_dump)
{
	DBG("\tRange: %d\n", parm[0] & 0xff);
	return len;
}

static FUNC_RECV(range_and_status_receive)
{
	int i;
	int numcics;

	msg->range = parm[0];
	numcics = msg->range + 1;

	/* No status for these messages */
	if ((messagetype == ISUP_CQR) || (messagetype == ISUP_CQM) || (messagetype == ISUP_GRS))
		return len;

	for (i = 0; i < numcics; i++) {
		if (parm[1 + (i/8)] & (1 << (i%8)))
			msg->status[i] = 1;
		else
			msg->status[i] = 0;
	}

	return len;
}

static FUNC_SEND(range_and_status_transmit)
{
	int i, statuslen = 0;
	int numcics = msg->range + 1;

	parm[0] = msg->range & 0xff;

	/* No status for these messages */
	if ((messagetype == ISUP_CQR) || (messagetype == ISUP_CQM) || (messagetype == ISUP_GRS))
		return 1;

	statuslen = (numcics / 8) + !!(numcics % 8);

	if (messagetype == ISUP_GRA) {
		for (i = 0; i < statuslen; i++) {
			parm[1 + i] = 0;
		}
	} else {
		for (i = 0; i < numcics; i++) {
			if (msg->status[i])
				parm[1 + (i/8)] |= (1 << (i % 8));
		}
	}

	return statuslen + 1;
}

static FUNC_DUMP(calling_party_num_dump)
{
	int oddeven = (parm[0] >> 7) & 0x1;
	char numbuf[64] = "";

	DBG("\tNature of address: %x\n", parm[0] & 0x7f);
	DBG("\tNI: %x\n", (parm[1] >> 7) & 0x1);
	DBG("\tNumbering plan: %x\n", (parm[1] >> 4) & 0x7);
	DBG("\tPresentation: %x\n", (parm[1] >> 2) & 0x3);
	DBG("\tScreening: %x\n", parm[1] & 0x3);

	isup_get_number(numbuf, &parm[2], len - 2, oddeven);

	DBG("\tAddress signals: %s\n", numbuf);

	return len;
}

static FUNC_RECV(calling_party_num_receive)
{
	int oddeven = (parm[0] >> 7) & 0x1;

	isup_get_number(msg->calling_party_num, &parm[2], len - 2, oddeven);

	msg->calling_nai = parm[0] & 0x7f;                /* Nature of Address Indicator */
	msg->presentation_ind = (parm[1] >> 2) & 0x3;
	msg->screening_ind = parm[1] & 0x3;

	return len;

}

static FUNC_SEND(calling_party_num_transmit)
{
	int oddeven, datalen;

	if (!msg->calling_party_num[0])
		return 0;

	isup_put_number(&parm[2], msg->calling_party_num, &datalen, &oddeven);

	parm[0] = (oddeven << 7) | msg->calling_nai;      /* Nature of Address Indicator */
	parm[1] = (1 << 4) |                            /* Assume E.164 ISDN numbering plan, calling number complete */
		((msg->presentation_ind & 0x3) << 2) |
		(msg->screening_ind & 0x3);

	return datalen + 2;
}

static FUNC_DUMP(originating_line_information_dump)
{
	char *name;

	switch (parm[0]) {
		case 0:
			name = (char *)" Plain Old Telephone Service POTS";
			break;
		case 1:
			name = (char *)" Multiparty line";
			break;
		case 2:
			name = (char *)" ANI Failure";
			break;
		case 3:
		case 4:
		case 5:
			name = (char *)" Unassigned";
			break;
		case 6:
			name = (char *)" Station Level Rating";
			break;
		case 7:
			name = (char *)" Special Operator Handling Required";
			break;
		case 8:
		case 9:
			name = (char *)"Unassigned";
			break;
		case 10:
			name = (char *)"Not assignable";
			break;
		case 11:
			name = (char *)"Unassigned";
			break;
		case 12:
		case 13:
		case 14:
		case 15:
		case 16:
		case 17:
		case 18:
		case 19:
			name = (char *)"Not assignable";
			break;
		case 20:
			name = (char *)"Automatic Identified Outward Dialing";
			break;
		case 21:
		case 22:
			name = (char *)"Unassigned";
			break;
		case 23:
			name = (char *)"Coin or Non-Coin";
			break;
		case 24:
		case 25:
			name = (char *)"Toll Free Service translated to POTS";
			break;
		case 26:
			name = (char *)"Unassigned";
			break;
		case 27:
			name = (char *)"Pay Station using Coin Control Signalling";
			break;
		case 28:
			name = (char *)"Unassigned";
			break;
		case 29:
			name = (char *)"Prison/Inmate Service";
			break;
		case 30:
		case 31:
		case 32:
			name = (char *)"Intercept";
			break;
		case 33:
			name = (char *)"Unassigned";
			break;
		case 34:
			name = (char *)"Telco Operator Handled Call";
			break;
		case 35:
		case 36:
		case 37:
		case 38:
		case 39:
			name = (char *)"Unassigned";
			break;
		case 40:
		case 41:
		case 42:
		case 43:
		case 44:
		case 45:
		case 46:
		case 47:
		case 48:
		case 49:
			name = (char *)"Unrestricted Use - locally determined by carrier";
			break;
		case 50:
		case 51:
			name = (char *)"Unassigned";
			break;
		case 52:
			name = (char *)"OUTWATS";
			break;
		case 53:
		case 54:
		case 55:
		case 56:
		case 57:
		case 58:
		case 59:
			name = (char *)"Unassigned";
			break;
		case 60:
			name = (char *)"TRS Unrestricted Line";
			break;
		case 61:
			name = (char *)"Cellular Wireless PCS Type 1";
			break;
		case 62:
			name = (char *)"Cellular Wireless PCS Type 2";
			break;
		case 63:
			name = (char *)"Cellular Wireless PCS Roaming";
			break;
		case 64:
		case 65:
			name = (char *)"Unassigned";
			break;
		case 66:
			name = (char *)"TRS Hotel Motel";
			break;
		case 67:
			name = (char *)"TRS Restricted Line";
			break;
		case 68:
		case 69:
			name = (char *)"Unassigned";
			break;
		case 70:
			name = (char *)"Pay Station No network Coin Control Signalling";
			break;
		case 71:
		case 72:
		case 73:
		case 74:
		case 75:
		case 76:
		case 77:
		case 78:
		case 79:
			name = (char *)"Unassigned";
			break;
		case 80:
		case 81:
		case 82:
		case 83:
		case 84:
		case 85:
		case 86:
		case 87:
		case 88:
		case 89:
			name = (char *)"Reserved";
			break;
		case 90:
		case 91:
		case 92:
			name = (char *)"Unassigned";
			break;
		case 93:
			name = (char *)"Private Virtual Network Type of service call";
			break;
		case 94:
		case 95:
		case 96:
		case 97:
		case 98:
		case 99:
			name = (char *)"Unassigned";
			break;

		default:
			name = (char *)"Unknown to Asterisk ";
	}
	DBG("\tLine info code: %s (%d)\n", name, parm[0]);

	return 1;
}

static FUNC_RECV(originating_line_information_receive)
{
	msg->oli_ani2 = parm[0];

	return 1;
}

static FUNC_SEND(originating_line_information_transmit)
{
	if (msg->oli_ani2 < 0) {  /* Allow dialplan to strip OLI parm if you don't want to resend what was received */
		return 0;
	} else if (msg->oli_ani2 < 99) {
		parm[0] = msg->oli_ani2;
		return 1;
	} else {
		parm[0] = 0x00; /* This value is setting OLI equal to POTS line. */
		return 1;
	}
}

static FUNC_DUMP(carrier_identification_dump)
{
	return len;
}

static FUNC_RECV(carrier_identification_receive)
{
	return len;
}

static FUNC_SEND(carrier_identification_transmit)
{
	parm[0] = 0x22;  /* 4 digit CIC */
	parm[1] = 0x00;  /* would send default 0000 */
	parm[2] = 0x00;

	return 3;
}
static FUNC_DUMP(jip_dump)
{
	char numbuf[64] = "";

	isup_get_number(numbuf, &parm[0], len , 0);
	DBG("\tJIP: %s\n", numbuf);
	return len;
}

static FUNC_RECV(jip_receive)
{
	isup_get_number(msg->jip_number, &parm[0], len, 0);
	return len;
}

static FUNC_SEND(jip_transmit)
{
	int oddeven, datalen;

	if  (msg->jip_number[0]) {
		isup_put_number(&parm[0], msg->jip_number, &datalen, &oddeven);
		return datalen;
	}
	return 0;
}

static FUNC_DUMP(hop_counter_dump)
{
	return 1;
}

static FUNC_RECV(hop_counter_receive)
{
	return 1;
}

static FUNC_SEND(hop_counter_transmit)
{
	parm[0] = 0x01; /* would send hop counter with value of 1 */
	return 1;
}

static FUNC_RECV(charge_number_receive)
{
	int oddeven = (parm[0] >> 7) & 0x1;

	isup_get_number(msg->charge_number, &parm[2], len - 2, oddeven);

	msg->charge_nai = parm[0] & 0x7f;                /* Nature of Address Indicator */
	msg->charge_num_plan = (parm[1] >> 4) & 0x7;

	return len;
}

static FUNC_DUMP(charge_number_dump)
{
	int oddeven = (parm[0] >> 7) & 0x1;
	char numbuf[64] = "";

	DBG("\tNature of address: %x\n", parm[0] & 0x7f);
	DBG("\tNumbering plan: %x\n", (parm[1] >> 4) & 0x7);

	isup_get_number(numbuf, &parm[2], len - 2, oddeven);

	DBG("\tAddress signals: %s\n", numbuf);

	return len;
}

static FUNC_SEND(charge_number_transmit)  //ANSI network
{
	int oddeven, datalen;

	if (!msg->charge_number[0])
		return 0;

	isup_put_number(&parm[2], msg->charge_number, &datalen, &oddeven);  /* use the value from callerid in sip.conf to fill charge number */

	parm[0] = (oddeven << 7) | msg->charge_nai;        /* Nature of Address Indicator = odd/even and ANI of the Calling party, subscriber number */
	parm[1] = (1 << 4) | 0x0;       //msg->charge_num_plan    /* Assume E.164 ISDN numbering plan, calling number complete and make sure reserved bits are zero */

	return datalen + 2;

}

static FUNC_SEND(continuity_ind_transmit)
{
	if (msg->cot_check_passed)
		parm[0] = 0x01;
	else
		parm[0] = 0x00;

	return 1;
}

static FUNC_RECV(continuity_ind_receive)
{
	if (0x1 & parm[0])
		msg->cot_check_passed = 1;
	else
		msg->cot_check_passed = 0;
	return 1;
}

static FUNC_DUMP(continuity_ind_dump)
{
	DBG("\tContinuity Check: %s\n", (0x01 & parm[0]) ? "successful" : "failed");

	return 1;
}

static FUNC_DUMP(circuit_group_supervision_dump)
{
	char *name;

	switch (parm[0] & 0x3) {
	case 0:
		name = (char *)"Maintenance oriented";
		break;
	case 1:
		name = (char *)"Hardware Failure oriented";
		break;
	case 2:
		name = (char *)"Reserved for national use";
		break;
	case 3:
		name = (char *)"Spare";
		break;
	default:
		name = (char *)"Huh?!";
	}
	DBG("\tType indicator: %s\n", name);

	return 1;
}

static FUNC_RECV(circuit_group_supervision_receive)
{
	msg->cicgroupsupervisiontype = 0x3 & parm[0];
	return 1;
}

static FUNC_SEND(circuit_group_supervision_transmit)
{
	parm[0] = msg->cicgroupsupervisiontype & 0x3;
	return 1;
}

static FUNC_DUMP(event_info_dump)
{
	char *name;

	switch (parm[0]) {
		case 0:
			name = (char *)"spare";
			break;
		case 1:
			name = (char *)"ALERTING";
			break;
		case 2:
			name = (char *)"PROGRESS";
			break;
		case 3:
			name = (char *)"In-band information or an appropriate pattern is now available";
			break;
		case 4:
			name = (char *)"Call forward on busy";
			break;
		case 5:
			name = (char *)"Call forward on no reply";
			break;
		case 6:
			name = (char *)"Call forward unconditional";
			break;
		default:
			name = (char *)"Spare";
			break;
	}
	DBG("\t%s\n", name);
	return 1;
}

static FUNC_RECV(event_info_receive)
{
	msg->event_info = parm[0];
	return 1;
}

static FUNC_SEND(event_info_transmit)
{
	parm[0] = msg->event_info;
	return 1;
}

static FUNC_DUMP(redirection_info_dump)
{
	char *redirect_ind, *orig_redir_reas, *redir_reas;

	switch (parm[0] & 0x7) {
		case 0:
			redirect_ind = (char *)"No Redirection (national use)";
			break;
		case 1:
			redirect_ind = (char *)"Call rerouted (national use)";
			break;
		case 2:
			redirect_ind = (char *)"Call rerouted, all rediection information presentation restricted (national use)";
			break;
		case 3:
			redirect_ind = (char *)"Call diverted";
			break;
		case 4:
			redirect_ind = (char *)"Call diverted, all redirection information presentation restricted";
			break;
		case 5:
			redirect_ind = (char *)"Call rerouted, redirection number presentation restricted (national use)";
			break;
		case 6:
			redirect_ind = (char *)"Call diversion, redirection number presentation restricted (national use)";
			break;
		case 7:
			redirect_ind = (char *)"spare";
			break;
		default:
			redirect_ind = (char *)"Unknown";
			break;
	}

	DBG("\tRedirecting indicator: %s (%d)\n", redirect_ind, parm[0] & 0x7);

	switch ((parm[0] >> 4) & 0xf) {
		case 0:
			orig_redir_reas = (char *)"Unknown/not available";
			break;
		case 1:
			orig_redir_reas = (char *)"User busy (national use)";
			break;
		case 2:
			orig_redir_reas = (char *)"No reply (national use)";
			break;
		case 3:
			orig_redir_reas = (char *)"Unconditional (national use)";
			break;
		default:
			orig_redir_reas = (char *)"spare";
			break;
	}

	DBG("\tOriginal redirection reason: %s (%d)\n", orig_redir_reas, (parm[0] >> 4) & 0xf);
	DBG("\tRedirection counter: %d\n", parm[1] & 0x7);

	switch ((parm[1] >> 4) & 0xf) {
		case 0:
			redir_reas = (char *)"Unknown/not available";
			break;
		case 1:
			redir_reas = (char *)"User busy";
			break;
		case 2:
			redir_reas = (char *)"No reply";
			break;
		case 3:
			redir_reas = (char *)"Unconditional";
			break;
		case 4:
			redir_reas = (char *)"Deflection during alerting";
			break;
		case 5:
			redir_reas = (char *)"Deflection immediate response";
			break;
		case 6:
			redir_reas = (char *)"Mobile subscriber not reachable";
			break;
		default:
			redir_reas = (char *)"spare";
			break;
	}

	DBG("\tRedirecting reason: %s (%d)\n", redir_reas, (parm[1] >> 4) & 0xf);

	return 2;
}

static FUNC_RECV(redirection_info_receive)
{
	return 2;
}

static FUNC_SEND(redirection_info_transmit)
{
	return 2;
}

static FUNC_RECV(generic_name_receive)
{
	msg->generic_name_typeofname = (parm[0] >> 5) & 0x7;
	msg->generic_name_avail = (parm[0] >> 4) & 0x1;
	msg->generic_name_presentation = parm[0] & 0x3;
	msg->generic_name = string((char *)&parm[1], len - 1);
	return len;
}

static FUNC_DUMP(generic_name_dump)
{
	unsigned int typeofname = (parm[0] >> 5) & 0x7;
	unsigned int avail = (parm[0] >> 4) & 0x1;
	unsigned int presentation = parm[0] & 0x3;
	char name[ISUP_MAX_NAME + 1];

	memcpy(name, &parm[1], len - 1);

	DBG("\tType of Name: %s (%d)\n", (typeofname == 1) ? "Calling Name" : "Unknown", typeofname);
	DBG("\tAvail: %s (%d)\n", (avail == 1) ? "Name not available" : "Name available, or availability unknown", avail);
	DBG("\tPresentation: %d\n",  presentation);
	DBG("\tName: %s\n", name);

	return len;
}

static FUNC_SEND(generic_name_transmit)
{
	int namelen = msg->generic_name.length();

	/* Check to see if generic name is set before we try to add it */
	if (!msg->generic_name[0])
		return 0;

	parm[0] = (msg->generic_name_typeofname << 5) | ((msg->generic_name_avail & 0x1) << 4) | (msg->generic_name_presentation & 0x3);
	memcpy(&parm[1], msg->generic_name.c_str(), namelen);

	return namelen + 1;
}

static FUNC_DUMP(generic_address_dump)
{
	int oddeven = (parm[1] >> 7) & 0x1;
	char numbuf[64] = "";

	DBG("\tType of address: %x\n", parm[0]);
	DBG("\tNature of address: %x\n", parm[1] & 0x7f);
	DBG("\tOddEven: %x\n", (parm[1] >> 7) & 0x1);
	DBG("\tReserved: %x\n", parm[2] & 0x3);
	DBG("\tPresentation: %x\n", (parm[2] >> 2) & 0x3);
	DBG("\tNumbering plan: %x\n", (parm[2] >> 4) & 0x7);

	isup_get_number(numbuf, &parm[3], len - 3, oddeven);

	DBG("\tAddress signals: %s\n", numbuf);

	return len;
}

static FUNC_RECV(generic_address_receive)
{
	int oddeven = (parm[1] >> 7) & 0x1;

	msg->gen_add_type = parm[0];
	msg->gen_add_nai = parm[1] & 0x7f;
	msg->gen_add_pres_ind = (parm[2] >> 2) & 0x3;
	msg->gen_add_num_plan = (parm[2] >> 4) & 0x7;

	isup_get_number(msg->gen_add_number, &parm[3], len - 3, oddeven);

	return len;
}

static FUNC_SEND(generic_address_transmit)
{

	int oddeven, datalen;

	if (!msg->gen_add_number[0])
		return 0;

	isup_put_number(&parm[3], msg->gen_add_number, &datalen, &oddeven);

	parm[0] = msg->gen_add_type;
	parm[1] = (oddeven << 7) | msg->gen_add_nai;      /* Nature of Address Indicator */
	parm[2] = (msg->gen_add_num_plan << 4) |
		((msg->gen_add_pres_ind & 0x3) << 2) |
		( 0x00 & 0x3);

	return datalen + 3;
}


static FUNC_DUMP(generic_digits_dump)
{
	int oddeven = (parm[0] >> 5) & 0x7;
	char numbuf[64] = "";

	DBG("\tType of digits: %x\n", parm[0] & 0x1f);
	DBG("\tEncoding Scheme: %x\n", (parm[0] >> 5) & 0x7);
	isup_get_number(numbuf, &parm[1], len - 1, oddeven);
	DBG("\tAddress digits: %s\n", numbuf);

	return len;

}

static FUNC_RECV(generic_digits_receive)
{
	msg->gen_dig_scheme = (parm[0] >> 5) & 0x7;
	msg->gen_dig_type = parm[0] & 0x1f;

	isup_get_number(msg->gen_dig_number, &parm[1], len - 1, msg->gen_dig_scheme);
	return len;
}

static FUNC_SEND(generic_digits_transmit)
{
	int oddeven, datalen;

	if (!msg->gen_dig_number[0])
		return 0;

	switch (msg->gen_dig_type) {
		case 0:
		case 1:
		case 2: /* used for sending digit strings */
			isup_put_number(&parm[1], msg->gen_dig_number, &datalen, &oddeven);
			parm[0] = (oddeven << 5 ) | msg->gen_dig_type;
			break;
		case 3:	 /*used for sending BUSINESS COMM. GROUP IDENTIY type */
			isup_put_generic(&parm[1], msg->gen_dig_number, &datalen);
			parm[0] = (msg->gen_dig_scheme << 5 ) | msg->gen_dig_type;
			break;
		default:
			isup_put_number(&parm[1], msg->gen_dig_number, &datalen, &oddeven);
			parm[0] = (oddeven << 5 ) | msg->gen_dig_type;
			break;
	}
	return datalen + 1;
}

static FUNC_DUMP(original_called_num_dump)
{
	int oddeven = (parm[0] >> 7) & 0x1;
	char numbuf[64] = "";

	DBG("\tNature of address: %x\n", parm[0] & 0x7f);
	DBG("\tNumbering plan: %x\n", (parm[1] >> 4) & 0x7);
	DBG("\tPresentation: %x\n", (parm[1] >> 2) & 0x3);

	isup_get_number(numbuf, &parm[2], len - 2, oddeven);

	DBG("\tAddress signals: %s\n", numbuf);

	return len;
}

static FUNC_RECV(original_called_num_receive)
{
	int oddeven = (parm[0] >> 7) & 0x1;

	isup_get_number(msg->orig_called_num, &parm[2], len - 2, oddeven);

	msg->orig_called_nai = parm[0] & 0x7f;
	msg->orig_called_pres_ind = (parm[1] >> 2) & 0x3;
	msg->orig_called_screening_ind = parm[1] & 0x3;

	return len;
}

static FUNC_SEND(original_called_num_transmit)
{
	return len;
}

static FUNC_DUMP(echo_control_info_dump)
{
	unsigned char ba = parm[0] & 0x3;
	unsigned char dc = (parm[0] >> 2) & 0x3;
	unsigned char fe = (parm[0] >> 4) & 0x3;
	unsigned char hg = (parm[0] >> 6) & 0x3;
	char *ba_str, *dc_str, *fe_str, *hg_str;

	switch (ba) {
		case 0:
			ba_str = (char *)"no information";
			break;
		case 1:
			ba_str = (char *)"outgoing echo control device not included and not available";
			break;
		case 2:
			ba_str = (char *)"outgoing echo control device included";
			break;
		case 3:
			ba_str = (char *)"outgoing echo control device not included but available";
			break;
		default:
			ba_str = (char *)"unknown";
			break;
	}

	switch (dc) {
		case 0:
			dc_str = (char *)"no information";
			break;
		case 1:
			dc_str = (char *)"incoming echo control device not included and not available";
			break;
		case 2:
			dc_str = (char *)"incoming echo control device included";
			break;
		case 3:
			dc_str = (char *)"incoming echo control device not included but available";
			break;
		default:
			dc_str = (char *)"unknown";
			break;
	}

	switch (fe) {
		case 0:
			fe_str = (char *)"no information";
			break;
		case 1:
			fe_str = (char *)"outgoing echo control device activation request";
			break;
		case 2:
			fe_str = (char *)"outgoing echo control device deactivation request";
			break;
		case 3:
			fe_str = (char *)"spare";
			break;
		default:
			fe_str = (char *)"unknown";
			break;
	}

	switch (hg) {
		case 0:
			hg_str = (char *)"no information";
			break;
		case 1:
			hg_str = (char *)"incoming echo control device activation request";
			break;
		case 2:
			hg_str = (char *)"incoming echo control device deactivation request";
			break;
		case 3:
			hg_str = (char *)"spare";
			break;
		default:
			hg_str = (char *)"unknown";
			break;
	}

	DBG("\tOutgoing echo control device information: %s (%d)\n", ba_str, ba);
	DBG("\tIncoming echo control device information: %s (%d)\n", dc_str, dc);
	DBG("\tOutgoing echo control device request: %s (%d)\n", fe_str, fe);
	DBG("\tIncoming echo control device request: %s (%d)\n", hg_str, hg);

	return len;
}

static FUNC_DUMP(parameter_compat_info_dump)
{
	return len;
}

static FUNC_DUMP(propagation_delay_cntr_dump)
{
	DBG("\tDelay: %dms\n", (unsigned short)(((parm[0] & 0xff) << 8) | (parm[1] & 0xff)));
	return len;
}

static FUNC_RECV(propagation_delay_cntr_receive)
{
	msg->propagation_delay = (unsigned short)(((parm[0] & 0xff) << 8) | (parm[1] & 0xff));
	return len;
}

static FUNC_DUMP(circuit_state_ind_dump)
{
	unsigned char dcbits, babits, febits;
	char *ba_str = NULL, *dc_str = NULL, *fe_str = NULL;
	int i;

	for (i = 0; i < len; i++) {
		babits = parm[i] & 0x3;
		dcbits = (parm[i] >> 2) & 0x3;
		febits = (parm[i] >> 4) & 0x3;

		if (dcbits == 0) {
			switch (babits) {
				case 0:
					ba_str = (char *)"transient";
					break;
				case 1:
				case 2:
					ba_str = (char *)"spare";
					break;
				case 3:
					ba_str = (char *)"unequipped";
					break;
			}
		} else {
			switch (babits) {
				case 0:
					ba_str = (char *)"no blocking (active)";
					break;
				case 1:
					ba_str = (char *)"locally blocked";
					break;
				case 2:
					ba_str = (char *)"remotely blocked";
					break;
				case 3:
					ba_str = (char *)"locally and remotely blocked";
					break;
			}

			switch (dcbits) {
				case 1:
					dc_str = (char *)"circuit incoming busy";
					break;
				case 2:
					dc_str = (char *)"circuit outgoing busy";
					break;
				case 3:
					dc_str = (char *)"idle";
					break;
			}

			switch (febits) {
				case 0:
					fe_str = (char *)"no blocking (active)";
					break;
				case 1:
					fe_str = (char *)"locally blocked";
					break;
				case 2:
					fe_str = (char *)"remotely blocked";
					break;
				case 3:
					fe_str = (char *)"locally and remotely blocked";
					break;
			}

		}

		DBG("\tMaintenance blocking state: %s (%d)\n", ba_str, babits);
		if (!dcbits)
			continue;
		DBG("\tCall processing state: %s (%d)\n", dc_str, dcbits);
		DBG("\tHardware blocking state: %s (%d)\n", fe_str, febits);
	}
	return len;
}

static FUNC_SEND(circuit_state_ind_transmit)
{
	int numcics = msg->range + 1, i;

	for (i = 0; i < numcics; i++)
		parm[i] = msg->status[i];

	return numcics;
}

static FUNC_DUMP(tns_dump)
{
	DBG("\tType of Network: %x\n", (parm[0] >> 4) & 0x7);
	DBG("\tNetwork ID plan: %x\n", parm[0] & 0xf);
	DBG("\tNetwork ID: %x %x\n", parm[1], parm[2]);
	DBG("\tCircuit Code: %x\n", (parm[3] >> 4) & 0xf);

	return len;
}

static FUNC_SEND(tns_transmit)
{
	return 0;
}

static FUNC_RECV(tns_receive)
{
	return len;
}

static FUNC_SEND(lspi_transmit)
{
	/* On Nortel this needs to be set to ARM the RLT functionality. */
	/* This causes the Nortel switch to return the CALLREFERENCE Parm on the ACM of the outgoing call */
	/* This parm has more fields that can be set but Nortel DMS-250/500 needs it set as below */
	if (msg->lspi_scheme) {
		parm[0] = msg->lspi_scheme << 5 | msg->lspi_type;  /* only setting parms for NORTEL RLT on IMT trktype */
		return 1;
	}
	return 0;
}

static FUNC_RECV(lspi_receive)
{
	msg->lspi_type = parm[0] & 0x1f;
	msg->lspi_scheme = parm[0] >> 5 & 0x7;
	msg->lspi_context = parm[1] & 0xf;
	isup_get_number(msg->lspi_ident, &parm[2], len - 2, msg->lspi_scheme);

	return len;
}

static FUNC_DUMP(lspi_dump)
{
	DBG("\tLSPI Type: %x\n", parm[0] & 0x1f);
	DBG("\tEncoding Scheme: %x\n", (parm[0] >> 5) & 0x7);
	DBG("\tContext ID: %x\n", parm[1] & 0xf);
	DBG("\tSpare: %x\n", (parm[1] >> 4) & 0xf);
	DBG("\tLSP Identity: %x\n", parm[2]);

	return len;
}

static FUNC_DUMP(call_ref_dump)
{
	unsigned int ptc, callr;

	callr = parm[0] | (parm[1] << 8) | (parm[2] << 16);
	if (msg->proto_type == AmISUP::SS7_ANSI)
		ptc = parm[3] | (parm[4] << 8) | (parm[5] << 16);
	else
		ptc = parm[3] | (parm[4] << 8);

	DBG("\tCall identity: %d\n", callr);
	if (msg->proto_type == AmISUP::SS7_ANSI)
		DBG("\tPC: Net-CLstr-Mbr: %d-%d-%d\n",(ptc >> 16) & 0xff, (ptc >> 8) & 0xff, ptc & 0xff);
	else
		DBG("\tPC: 0x%x\n", ptc);

	return len;
}

static FUNC_SEND(call_ref_transmit)
{
	if (msg->call_ref_ident) {
		if (msg->proto_type == AmISUP::SS7_ANSI) {
			parm[0] = msg->call_ref_ident & 0xff;
			parm[1] = (msg->call_ref_ident >> 8) & 0xff;
			parm[2] = (msg->call_ref_ident >> 16) & 0xff;
			parm[3] = msg->call_ref_pc & 0xff;
			parm[4] = (msg->call_ref_pc >> 8) & 0xff;
			parm[5] = (msg->call_ref_pc >> 16) & 0xff;
			return 6;
		} else {
			parm[0] = msg->call_ref_ident & 0xff;
			parm[1] = (msg->call_ref_ident >> 8) & 0xff;
			parm[2] = (msg->call_ref_ident >> 16) & 0xff;
			parm[3] = msg->call_ref_pc & 0xff;
			parm[4] = (msg->call_ref_pc >> 8) & 0x3f;
			return 5;
		}
	}
	return 0;
}

static FUNC_RECV(call_ref_receive)
{
	if (msg->proto_type == AmISUP::SS7_ANSI) {
		msg->call_ref_ident = parm[0] | (parm[1] << 8) | (parm[2] << 16);
		msg->call_ref_pc = parm[3] | (parm[4] << 8) | (parm[5] << 16);
	} else {
		msg->call_ref_ident = parm[0] | (parm[1] << 8) | (parm[2] << 16);
		msg->call_ref_pc = parm[3] | ((parm[4] & 0x3f) << 8);
	}
	return len;
}

static FUNC_DUMP(facility_ind_dump)
{
	DBG("\tFacility Indicator: %x\n", parm[0]);
	return 1;
}

static FUNC_RECV(facility_ind_receive)
{
	return 1;
}

static FUNC_SEND(facility_ind_transmit)
{
	parm[0] = 0x10; /* Setting Value to Nortel DMS-250/500 needs for RLT */
	return 1;
}

static FUNC_DUMP(redirecting_number_dump)
{
	int oddeven = (parm[0] >> 7) & 0x1;
	char numbuf[64] = "";

	DBG("\tNature of address: %x\n", parm[0] & 0x7f);
	DBG("\tNI: %x\n", (parm[1] >> 7) & 0x1);
	DBG("\tNumbering plan: %x\n", (parm[1] >> 4) & 0x7);
	DBG("\tPresentation: %x\n", (parm[1] >> 2) & 0x3);
	DBG("\tScreening: %x\n", parm[1] & 0x3);

	isup_get_number(numbuf, &parm[2], len - 2, oddeven);

	DBG("\tAddress signals: %s\n", numbuf);

	return len;
}

static FUNC_RECV(redirecting_number_receive)
{
	int oddeven = (parm[0] >> 7) & 0x1;

	isup_get_number(msg->redirecting_num, &parm[2], len - 2, oddeven);

	msg->redirecting_num_nai = parm[0] & 0x7f;                /* Nature of Address Indicator */
	msg->redirecting_num_presentation_ind = (parm[1] >> 2) & 0x3;
	msg->redirecting_num_screening_ind = parm[1] & 0x3;

	return len;

}

static FUNC_SEND(redirecting_number_transmit)
{
	return 0;
}

static FUNC_DUMP(access_transport_dump)
{
	return len;
}
static FUNC_RECV(access_transport_receive)
{
	return len;
}

static FUNC_SEND(access_transport_transmit)
{
	return len;
}

struct parm_func {
	int parm;
	const char *name;
	FUNC_DUMP(*dump);
	FUNC_RECV(*receive);
	FUNC_SEND(*transmit);
};

static struct parm_func parms[] = {
	{ISUP_PARM_NATURE_OF_CONNECTION_IND, "Nature of Connection Indicator", nature_of_connection_ind_dump, nature_of_connection_ind_receive, nature_of_connection_ind_transmit },
	{ISUP_PARM_FORWARD_CALL_IND, "Forward Call Indicators", forward_call_ind_dump, forward_call_ind_receive, forward_call_ind_transmit },
	{ISUP_PARM_CALLING_PARTY_CAT, "Calling Party's Category", calling_party_cat_dump, calling_party_cat_receive, calling_party_cat_transmit},
	{ISUP_PARM_TRANSMISSION_MEDIUM_REQS, "Transmission Medium Requirements", transmission_medium_reqs_dump, transmission_medium_reqs_receive, transmission_medium_reqs_transmit},
	{ISUP_PARM_USER_SERVICE_INFO, "User Service Information", NULL, user_service_info_receive, user_service_info_transmit},
	{ISUP_PARM_CALLED_PARTY_NUM, "Called Party Number", called_party_num_dump, called_party_num_receive, called_party_num_transmit},
	{ISUP_PARM_CAUSE, "Cause Indicator", cause_dump, cause_receive, cause_transmit},
	{ISUP_PARM_CONTINUITY_IND, "Continuity Indicator", continuity_ind_dump, continuity_ind_receive, continuity_ind_transmit},
	{ISUP_PARM_ACCESS_TRANS, "Access Transport", access_transport_dump, access_transport_receive, access_transport_transmit},
	{ISUP_PARM_BUSINESS_GRP, "Business Group"},
	{ISUP_PARM_CALL_REF, "Call Reference", call_ref_dump, call_ref_receive, call_ref_transmit},
	{ISUP_PARM_CALLING_PARTY_NUM, "Calling Party Number", calling_party_num_dump, calling_party_num_receive, calling_party_num_transmit},
	{ISUP_PARM_CARRIER_ID, "Carrier Identification", carrier_identification_dump, carrier_identification_receive, carrier_identification_transmit},
	{ISUP_PARM_SELECTION_INFO, "Selection Information"},
	{ISUP_PARM_CHARGE_NUMBER, "Charge Number", charge_number_dump, charge_number_receive, charge_number_transmit},
	{ISUP_PARM_CIRCUIT_ASSIGNMENT_MAP, "Circuit Assignment Map"},
	{ISUP_PARM_CONNECTION_REQ, "Connection Request"},
	{ISUP_PARM_CUG_INTERLOCK_CODE, "Interlock Code"},
	{ISUP_PARM_EGRESS_SERV, "Egress Service"},
	{ISUP_PARM_GENERIC_ADDR, "Generic Address", generic_address_dump, generic_address_receive, generic_address_transmit},
	{ISUP_PARM_GENERIC_DIGITS, "Generic Digits", generic_digits_dump, generic_digits_receive, generic_digits_transmit},
	{ISUP_PARM_GENERIC_NAME, "Generic Name", generic_name_dump, generic_name_receive, generic_name_transmit},
	{ISUP_PARM_TRANSIT_NETWORK_SELECTION, "Transit Network Selection", tns_dump, tns_receive, tns_transmit},
	{ISUP_PARM_GENERIC_NOTIFICATION_IND, "Generic Notification Indication"},
	{ISUP_PARM_PROPAGATION_DELAY, "Propagation Delay Counter", propagation_delay_cntr_dump,propagation_delay_cntr_receive},
	{ISUP_PARM_HOP_COUNTER, "Hop Counter", hop_counter_dump, hop_counter_receive, hop_counter_transmit},
	{ISUP_PARM_BACKWARD_CALL_IND, "Backward Call Indicator", backward_call_ind_dump, backward_call_ind_receive, backward_call_ind_transmit},
	{ISUP_PARM_OPT_BACKWARD_CALL_IND, "Optional Backward Call Indicator", opt_backward_call_ind_dump, opt_backward_call_ind_receive, NULL},
	{ISUP_PARM_CIRCUIT_GROUP_SUPERVISION_IND, "Circuit Group Supervision Indicator", circuit_group_supervision_dump, circuit_group_supervision_receive, circuit_group_supervision_transmit},
	{ISUP_PARM_RANGE_AND_STATUS, "Range and status", range_and_status_dump, range_and_status_receive, range_and_status_transmit},
	{ISUP_PARM_EVENT_INFO, "Event Information", event_info_dump, event_info_receive, event_info_transmit},
	{ISUP_PARM_OPT_FORWARD_CALL_INDICATOR, "Optional forward call indicator"},
	{ISUP_PARM_LOCATION_NUMBER, "Location Number"},
	{ISUP_PARM_ORIG_LINE_INFO, "Originating line information", originating_line_information_dump, originating_line_information_receive, originating_line_information_transmit},
	{ISUP_PARM_REDIRECTION_INFO, "Redirection Information", redirection_info_dump, redirection_info_receive, redirection_info_transmit},
	{ISUP_PARM_ORIGINAL_CALLED_NUM, "Original called number", original_called_num_dump, original_called_num_receive, original_called_num_transmit},
	{ISUP_PARM_JIP, "Jurisdiction Information Parameter", jip_dump, jip_receive, jip_transmit},
	{ISUP_PARM_ECHO_CONTROL_INFO, "Echo Control Information", echo_control_info_dump, NULL, NULL},
	{ISUP_PARM_PARAMETER_COMPAT_INFO, "Parameter Compatibility Information", parameter_compat_info_dump, NULL, NULL},
	{ISUP_PARM_CIRCUIT_STATE_IND, "Circuit State Indicator", circuit_state_ind_dump, NULL, circuit_state_ind_transmit},
	{ISUP_PARM_LOCAL_SERVICE_PROVIDER_IDENTIFICATION, "Local Service Provider ID", lspi_dump, lspi_receive, lspi_transmit},
	{ISUP_PARM_FACILITY_IND, "Facility Indicator", facility_ind_dump, facility_ind_receive, facility_ind_transmit},
	{ISUP_PARM_REDIRECTING_NUMBER, "Redirecting Number", redirecting_number_dump, redirecting_number_receive, redirecting_number_transmit},
	{ISUP_PARM_ACCESS_DELIVERY_INFO, "Access Delivery Information", },
};

static const char * param2str(int parm)
{
	int x;
	int totalparms = sizeof(parms)/sizeof(struct parm_func);
	for (x = 0; x < totalparms; x++)
		if (parms[x].parm == parm)
			return parms[x].name;

	return "Unknown";
}


AmISUP::AmISUP():
	proto_type(SS7_UNKNOWN),
	_buf(NULL),
	_len(0),
	message_type(ISUP_UNDEF)
{ }

AmISUP::AmISUP(const AmISUP& p_isup_msg)
{
	delete[] _buf;
}

void AmISUP::clear()
{
	_len = 0;
	delete[] _buf;

	version.clear();
	base_version.clear();
	proto_type = SS7_UNKNOWN;
	message_type = ISUP_UNDEF;
}

int AmISUP::parse(const AmMimeBody *body)
{
	clear();

	if(parse_mime(body)){
		ERROR("isup mime headers parse error");
		return -1;
	}
	if(proto_type!=SS7_ANSI and proto_type != SS7_ITU){
		ERROR("unsupported SS7 standard: %s",
			  proto_type_get_str(proto_type));
		return -1;
	}
	DBG("parse ISUP payload as %s",proto_type_get_str(proto_type));
	return parse_payload((const char *)body->getPayload(),body->getLen());
}

static AmISUP::isup_proto_type get_isup_proto_type(const string &s){
	// https://tools.ietf.org/rfc/rfc3204.txt
	const static string itu_92("itu-t92+");
	const static string ansi00("ansi00");

	if(s==itu_92){
		return AmISUP::SS7_ITU;
	} else if(s==ansi00){
		return AmISUP::SS7_ANSI;
	}
	return AmISUP::SS7_UNKNOWN;
}

int AmISUP::parse_mime(const AmMimeBody *body)
{
	const static string version_param("version");
	const static string base_param("base");

	const AmContentType &ct = body->getContentType();

	for(AmContentType::Params::const_iterator i = ct.params.begin();
		i!=ct.params.end();i++)
	{
		const AmContentType::Param &p = **i;
		//DBG("name = %s, value = %s",p.name.c_str(),p.value.c_str());
		if(p.name==version_param){
			version = p.value;
		} else if(p.name==base_param){
			base_version = p.value;
		}
	}

	if(version.empty()){
		DBG("missed mandatory parameter 'version'");
		return -1;
	}

	DBG("got ISUP payload version: '%s', base: '%s'",
		version.c_str(),base_version.c_str());

	proto_type = get_isup_proto_type(version);
	if(SS7_UNKNOWN==proto_type){
		DBG("unsupported ISUP payload version '%s'. try failover to base",
			version.c_str());
		if(base_version.empty()){
			ERROR("unsupported ISUP payload version and no base version to failover");
			return -1;
		}
		proto_type = get_isup_proto_type(base_version);
		if(SS7_UNKNOWN==proto_type){
			ERROR("unsupported ISUP payload base_version '%s'. give up",
				base_version.c_str());
			return -1;
		}
	}

	return 0;
}

int AmISUP::parse_payload(const char* buf, size_t len)
{
	//DBG("%s(%p,%ld)",FUNC_NAME,buf,len);

	//save buf
	_buf = new char[len];
	memcpy(_buf,buf,len);
	_len =  len;


	struct isup_h *mh;
	int *parms = NULL;
	int offset = 0;
	int ourmessage = -1;
	int fixedparams = 0, varparams = 0, optparams = 0;
	int res;
	size_t x;
	unsigned char *opt_ptr = NULL;

	mh = (struct isup_h*) buf;

	//get message type
	for (x = 0; x < sizeof(messages)/sizeof(struct message_data); x++)
		if (messages[x].messagetype == mh->type)
			ourmessage = x;

	if (ourmessage < 0) {
		ERROR("uknown ISUP message type: 0x%02x",mh->type);
		return -1;
	}

	message_data &md = messages[ourmessage];
	message_type  = mh->type;

	fixedparams = md.mand_fixed_params;
	varparams = md.mand_var_params;
	parms = md.param_list;
	optparams = md.opt_params;

	if(proto_type == SS7_ANSI) {
		switch(md.messagetype){
		case ISUP_IAM:
			fixedparams = 3;
			varparams = 2;
			parms = ansi_iam_params;
			break;
		case ISUP_RLC:
			optparams = 0;
			break;
		default:
			break;
		}
	}

	//parse fixed params
	for (x = 0; x < (size_t)fixedparams; x++) {
		res = parse_param(parms[x],(const char *)(mh->data + offset), len, PARM_TYPE_FIXED);
		if(res < 0) {
			ERROR("Unable to parse mandatory fixed parameter '%s'", param2str(parms[x]));
			return -1;
		}
		len -= res;
		offset += res;
	}

	if (varparams) {
		offset += varparams; /* add one for the optionals */
		len -= varparams;
	}

	if (optparams) {
		opt_ptr = &mh->data[offset++];
		len++;
	}

	for (; (x - fixedparams) < (size_t)varparams; x++) {
		res = parse_param(parms[x], (const char *)(mh->data + offset), len, PARM_TYPE_VARIABLE);
		if(res < 0) {
			ERROR("Unable to parse mandatory variable parameter '%s'", param2str(parms[x]));
			return -1;
		}
		len -= res;
		offset += res;
	}

	if (optparams && *opt_ptr) {
		while ((len > 0) && (mh->data[offset] != 0)) {
			struct isup_parm_opt *optparm = (struct isup_parm_opt *)(mh->data + offset);
			res = parse_param(optparm->type, (const char *)(mh->data + offset), optparm->len, PARM_TYPE_OPTIONAL);
			if (res < 0) {
				WARN("Unhandled optional parameter 0x%x '%s'",
					 optparm->type, param2str(optparm->type));
				res = optparm->len + 2;
			}
			len -= res;
			offset += res;
		}
	}

	return 0;
}


int AmISUP::parse_param(int parm, const char* parmbuf, size_t maxlen,isup_parm_type parmtype)
{
	int x;
	int len = 0;
	struct isup_parm_opt *optparm = NULL;
	int totalparms = sizeof(parms)/sizeof(struct parm_func);

	for (x = 0; x < totalparms; x++) {
		if (parms[x].parm != parm)
			continue;

#ifdef DUMP_ON_PARSING
		DBG("%s:\n", parms[x].name ? parms[x].name : "Unknown");
#endif
		DBG("receive_func: %p, type: %d, buf: %p, len: %ld",parms[x].receive,parmtype,parmbuf,maxlen);
		if (parms[x].receive) {
			switch (parmtype) {
			case PARM_TYPE_FIXED:
				len = parms[x].receive(this, message_type, (unsigned char *)parmbuf, maxlen);
#ifdef DUMP_ON_PARSING
				if(parms[x].dump)
					parms[x].dump(this, message_type, (unsigned char *)parmbuf, maxlen);
#endif
				break;
			case PARM_TYPE_VARIABLE:
				parms[x].receive(this, message_type, (unsigned char *)parmbuf + 1, parmbuf[0]);
#ifdef DUMP_ON_PARSING
				if(parms[x].dump)
					parms[x].dump(this, message_type, (unsigned char *)parmbuf + 1, parmbuf[0]);
#endif
				len = 1 + parmbuf[0];
				break;
			case PARM_TYPE_OPTIONAL:
				optparm = (struct isup_parm_opt *)parmbuf;
				parms[x].receive(this, message_type, optparm->data, optparm->len);
#ifdef DUMP_ON_PARSING
				if(parms[x].dump)
					parms[x].dump(this, message_type, optparm->data, optparm->len);
#endif
				len = 2 + optparm->len;
				break;
			}
		} else {
			switch (parmtype) {
			case PARM_TYPE_VARIABLE:
				len = parmbuf[0] + 1;
				break;
			case PARM_TYPE_OPTIONAL:
				optparm = (struct isup_parm_opt *)parmbuf;
				len = optparm->len + 2;
				break;
			case PARM_TYPE_FIXED:
				WARN("missed receive function for fixed param of type: 0x%02x",parm);
				break;
			}
		}
		return len;
	}
	optparm = (struct isup_parm_opt *)parmbuf;
	DBG("Unknown Parameter (0x%x):\n",optparm->type);
	return optparm->len + 2;
}


bool AmISUP::operator == (const AmISUP& other) const
{
	return false;
}

void AmISUP::getInfo(AmArg &ret) const
{
	ret["version"] = version;
	ret["base"] = base_version;
	ret["type"] = string(message2str(message_type));
	ret["called_party_num"] = called_party_num;
	ret["redirecting_num"] = redirecting_num;
	ret["original_called_number"] = orig_called_num;
}

void AmISUP::raw_dump() const
{
	dump_buffer("AmISUP::raw_dump",_buf,_len);
}

void AmISUP::dump() const
{
	std::stringstream s;
	int hex;

	s << std::setfill('0');

	s << "version: " << version << std::endl;
	hex = message_type&0xff;
	s << "message_type: 0x" << std::setw(2) << std::hex << hex <<
		 " (" << message2str(message_type) <<")" << std::endl;
	s << "called_party_num: " << called_party_num << std::endl;
	s << "redirecting_num: " << redirecting_num << std::endl;
	s << "original_called_number: " << orig_called_num << std::endl;
	s << "propagation_delay: " << std::dec << propagation_delay << " ms" << std::endl;

	DBG("AmISUP[%p]::dump():\n%s",
		this,s.str().c_str());
}

bool AmISUP::validate()
{
	//TODO: https://tools.ietf.org/html/draft-ietf-sip-overlap-01
	if(message_type==ISUP_IAM && !calling_party_num_finite){
		ERROR("signalling overlaping is not supported yet");
		return false;
	}
	return true;
}
