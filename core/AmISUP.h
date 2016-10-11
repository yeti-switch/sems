/*
 * class uses parts of code from project:
 * http://www.asterisk.org/downloads/libss7
 */

#ifndef __ISUPparser__
#define __ISUPparser__

#include "AmArg.h"
#include "AmMimeBody.h"

#define ISUP_MAX_NUM 64
/* From GR-317 for the generic name filed: 15 + 1 */
#define ISUP_MAX_NAME 16

/**
 * \brief The ISUP parser class.
 */
class AmISUP
{
	char *_buf;
	size_t _len;

	enum isup_parm_type {
		PARM_TYPE_FIXED  = 1,
		PARM_TYPE_VARIABLE,
		PARM_TYPE_OPTIONAL
	};

	int parse_mime(const AmMimeBody *body);
	int parse_payload(const char* buf, size_t len);
	int parse_param(int parm, const char* parmbuf, size_t maxlen,isup_parm_type parmtype);

  public:

	AmISUP();
	AmISUP(const AmISUP& p_isup_msg);

	/**
	 * Parse the ISUP message passed in buffer
	 * @return !=0 if error encountered.
	 */
	int parse(const AmMimeBody *body);
	bool operator == (const AmISUP& other) const;
	void clear();
	void raw_dump() const;
	void dump() const;
	void getInfo(AmArg &ret) const;

	/**
	 * @brief validate
	 * @return true if supported, false otherwise
	 */
	bool validate();

	/* SS7 types */
	enum isup_proto_type {
		SS7_ITU = 0,
		SS7_ANSI,
		SS7_UNKNOWN
	};
	isup_proto_type proto_type;
	string version;
	string base_version;

	// parsed ISUP fields
	unsigned char message_type;
	string called_party_num;
	unsigned char called_nai;
	string calling_party_num;
	bool calling_party_num_finite;
	unsigned char calling_party_cat;
	unsigned char calling_nai;
	unsigned char presentation_ind;
	unsigned char screening_ind;
	string  charge_number;
	unsigned char charge_nai;
	unsigned char charge_num_plan;
	unsigned char gen_add_num_plan;
	unsigned char gen_add_nai;
	string gen_add_number;
	unsigned char gen_add_pres_ind;
	unsigned char gen_add_type;
	string gen_dig_number;
	unsigned char gen_dig_type;
	unsigned char gen_dig_scheme;
	string jip_number;
	unsigned char lspi_type;
	unsigned char lspi_scheme;
	unsigned char lspi_context;
	unsigned char lspi_spare;
	string lspi_ident;
	int oli_ani2;
	unsigned int call_ref_ident;
	unsigned int call_ref_pc;
	string orig_called_num;
	unsigned char orig_called_nai;
	unsigned char orig_called_pres_ind;
	unsigned char orig_called_screening_ind;
	string redirecting_num;
	unsigned char redirecting_num_nai;
	unsigned char redirecting_num_presentation_ind;
	unsigned char redirecting_num_screening_ind;
	unsigned char generic_name_typeofname;
	unsigned char generic_name_avail;
	unsigned char generic_name_presentation;
	string generic_name;
	int range;
	unsigned char status[255];
	int transcap;
	int l1prot;
	int cause;
	int causecode;
	int causeloc;
	int cot_check_passed;
	int cot_check_required;
	int cicgroupsupervisiontype;
	unsigned char event_info;
	unsigned short cic;
	unsigned char sls;
	/* set DPC according to CIC's DPC, not linkset */
	unsigned int dpc;
	/* Backward Call Indicator variables */
	unsigned char called_party_status_ind;
	unsigned short propagation_delay;
};

#endif

// Local Variables:
// mode:C++
// End:
