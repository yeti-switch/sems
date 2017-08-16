#include "AmUtils.h"
#include "sip/parse_common.h"
#include "log.h"

/*
  http://www.unicode.org/versions/Unicode7.0.0/UnicodeStandard-7.0.pdf
  page 124, 3.9 "Unicode Encoding Forms", "UTF-8"


  Table 3-7. Well-Formed UTF-8 Byte Sequences
  -----------------------------------------------------------------------------
  |  Code Points        | First Byte | Second Byte | Third Byte | Fourth Byte |
  |  U+0000..U+007F     |     00..7F |             |            |             |
  |  U+0080..U+07FF     |     C2..DF |      80..BF |            |             |
  |  U+0800..U+0FFF     |         E0 |      A0..BF |     80..BF |             |
  |  U+1000..U+CFFF     |     E1..EC |      80..BF |     80..BF |             |
  |  U+D000..U+D7FF     |         ED |      80..9F |     80..BF |             |
  |  U+E000..U+FFFF     |     EE..EF |      80..BF |     80..BF |             |
  |  U+10000..U+3FFFF   |         F0 |      90..BF |     80..BF |      80..BF |
  |  U+40000..U+FFFFF   |     F1..F3 |      80..BF |     80..BF |      80..BF |
  |  U+100000..U+10FFFF |         F4 |      80..8F |     80..BF |      80..BF |
  -----------------------------------------------------------------------------
*/

enum utf8_fsm_state {
	ST_COMPLETED = 0,

	ST_C2DF_80BF_2nd,

	ST_E0_A0BF_80BF_2nd,
	ST_E0_A0BF_80BF_3rd,

	ST_E1EC_80BF_80BF_2nd,
	ST_E1EC_80BF_80BF_3rd,

	ST_ED_809F_80BF_2nd,
	ST_ED_809F_80BF_3rd,

	ST_EEEF_80BF_80BF_2nd,
	ST_EEEF_80BF_80BF_3rd,

	ST_F0_90BF_80BF_80BF_2nd,
	ST_F0_90BF_80BF_80BF_3rd,
	ST_F0_90BF_80BF_80BF_4th,

	ST_F1F3_80BF_80BF_80BF_2nd,
	ST_F1F3_80BF_80BF_80BF_3rd,
	ST_F1F3_80BF_80BF_80BF_4th,

	ST_F4_808F_80BF_80BF_2nd,
	ST_F4_808F_80BF_80BF_3rd,
	ST_F4_808F_80BF_80BF_4th
};

static const struct {
	unsigned char start;
	unsigned char end;
	utf8_fsm_state next_state;
} utf8_state2transition[] = {
	{ 0x00, 0x7F, ST_COMPLETED },

	{ 0x80, 0xBF, ST_COMPLETED },

	{ 0xA0, 0XBF, ST_E0_A0BF_80BF_3rd },
	{ 0x80, 0xBF, ST_COMPLETED },

	{ 0x80, 0xBF, ST_E1EC_80BF_80BF_3rd },
	{ 0x80, 0xBF, ST_COMPLETED },

	{ 0x80, 0x9F, ST_ED_809F_80BF_3rd },
	{ 0x80, 0xBF, ST_COMPLETED },

	{ 0x80, 0xBF, ST_EEEF_80BF_80BF_3rd },
	{ 0x80, 0xBF, ST_COMPLETED },

	{ 0x90, 0xBF, ST_F0_90BF_80BF_80BF_3rd },
	{ 0x80, 0xBF, ST_F0_90BF_80BF_80BF_4th },
	{ 0x80, 0xBF, ST_COMPLETED },

	{ 0x80, 0xBF, ST_F1F3_80BF_80BF_80BF_3rd },
	{ 0x80, 0xBF, ST_F1F3_80BF_80BF_80BF_4th },
	{ 0x80, 0xBF, ST_COMPLETED },

	{ 0x80, 0x8F, ST_F4_808F_80BF_80BF_3rd },
	{ 0x80, 0xBF, ST_F4_808F_80BF_80BF_4th },
	{ 0x80, 0xBF, ST_COMPLETED },
};

static const char *seq_desc[] = {
	"00-7F",
	"C2-DF,80-BF",
	"E0,A0-BF,80-BF",
	"E1-EC,80-BF,80-BF",
	"ED,80-9F,80-BF",
	"EE-EF,80-BF,80-BF",
	"F0,90-BF,80-BF,80-BF",
	"F1-F3,80-BF,80-BF,80-BF",
	"F4,80-8F,80-BF,80-BF"
};

static const char *utf8_state2seq_description[] = {
	seq_desc[0],
	seq_desc[1],
	seq_desc[2],seq_desc[2],
	seq_desc[3],seq_desc[3],
	seq_desc[4],seq_desc[4],
	seq_desc[5],seq_desc[5],
	seq_desc[6],seq_desc[6],seq_desc[6],
	seq_desc[7],seq_desc[7],seq_desc[7],
	seq_desc[8],seq_desc[8],seq_desc[8]
};

static const int utf8_state2byte_num[] = {
	1,
	2,
	2, 3,
	2, 3,
	2, 3,
	2, 3,
	2, 3, 4,
	2, 3, 4,
	2, 3, 4
};
static const int utf8_state2seq_byte_num[] = {
	1,
	2,
	3, 3,
	3, 3,
	3, 3,
	3, 3,
	4, 4, 4,
	2, 4, 4,
	4, 4, 4
};

#define VALIDATE_RANGE(condition_state) \
	case condition_state: \
		if(IS_IN(c, \
			utf8_state2transition[condition_state].start, \
			utf8_state2transition[condition_state].end)) \
		{ \
			st = utf8_state2transition[condition_state].next_state; \
			break; \
		} else { \
			WARN("unexpected value %02X at %d byte in %d bytes sequence. " \
				"expected to be within %02X..%02X. " \
				"pattern: %s", \
				c, \
				utf8_state2byte_num[st], \
				utf8_state2seq_byte_num[st], \
				utf8_state2transition[condition_state].start, \
				utf8_state2transition[condition_state].end, \
				utf8_state2seq_description[st]); \
			INVALID_SEQUENCE_ACTION(); \
		}

#define DEFINE_RANGE_VALIDATORS \
	VALIDATE_RANGE(ST_C2DF_80BF_2nd); \
	VALIDATE_RANGE(ST_E0_A0BF_80BF_2nd); \
	VALIDATE_RANGE(ST_E0_A0BF_80BF_3rd); \
	VALIDATE_RANGE(ST_E1EC_80BF_80BF_2nd); \
	VALIDATE_RANGE(ST_E1EC_80BF_80BF_3rd); \
	VALIDATE_RANGE(ST_ED_809F_80BF_2nd); \
	VALIDATE_RANGE(ST_ED_809F_80BF_3rd); \
	VALIDATE_RANGE(ST_EEEF_80BF_80BF_2nd); \
	VALIDATE_RANGE(ST_EEEF_80BF_80BF_3rd); \
	VALIDATE_RANGE(ST_F0_90BF_80BF_80BF_2nd); \
	VALIDATE_RANGE(ST_F0_90BF_80BF_80BF_3rd); \
	VALIDATE_RANGE(ST_F0_90BF_80BF_80BF_4th); \
	VALIDATE_RANGE(ST_F1F3_80BF_80BF_80BF_2nd); \
	VALIDATE_RANGE(ST_F1F3_80BF_80BF_80BF_3rd); \
	VALIDATE_RANGE(ST_F1F3_80BF_80BF_80BF_4th); \
	VALIDATE_RANGE(ST_F4_808F_80BF_80BF_2nd); \
	VALIDATE_RANGE(ST_F4_808F_80BF_80BF_3rd) \
	VALIDATE_RANGE(ST_F4_808F_80BF_80BF_4th)

#define SEQUENCE_CLASSIFIER_CASE(value,next_state) \
	case value: \
		st = next_state; \
		continue; \

#define SEQUENCE_CLASSIFIER_RANGE(start,end,next_state) \
	if(IS_IN(c,start,end)) { \
		st = next_state; \
		continue; \
	}

#define DEFINE_SEQUENCE_CLASSIFIER \
	case ST_COMPLETED: \
		if(IS_IN(c,0x00,0x7F)) { \
			continue; \
		} \
		switch(c) { \
		SEQUENCE_CLASSIFIER_CASE(0xE0,ST_E0_A0BF_80BF_2nd); \
		SEQUENCE_CLASSIFIER_CASE(0xED,ST_ED_809F_80BF_2nd); \
		SEQUENCE_CLASSIFIER_CASE(0xF0,ST_F0_90BF_80BF_80BF_2nd); \
		SEQUENCE_CLASSIFIER_CASE(0xF4,ST_F4_808F_80BF_80BF_2nd); \
		default: \
			SEQUENCE_CLASSIFIER_RANGE(0xC2,0xDF,ST_C2DF_80BF_2nd); \
			SEQUENCE_CLASSIFIER_RANGE(0xE1,0xEC,ST_E1EC_80BF_80BF_2nd); \
			SEQUENCE_CLASSIFIER_RANGE(0xEE,0xEF,ST_EEEF_80BF_80BF_2nd); \
			SEQUENCE_CLASSIFIER_RANGE(0xF1,0xF3,ST_F1F3_80BF_80BF_80BF_2nd); \
		} \
		WARN("unexpected value %02X on sequence start ",c); \
		INVALID_SEQUENCE_START_ACTION(); \


bool is_valid_utf8(const std::string &s)
{
#define INVALID_SEQUENCE_ACTION(condition_state) return false;
#define INVALID_SEQUENCE_START_ACTION(st); return false;

	utf8_fsm_state st = ST_COMPLETED;

	for(const unsigned char &c: s) {
		switch(st) {
		DEFINE_SEQUENCE_CLASSIFIER;
		DEFINE_RANGE_VALIDATORS
		default:
			ERROR("unknown state: %d",st);
			return false;
		}
	}

	if(st!=ST_COMPLETED) {
		WARN("incompleted utf8 multibyte sequence. "
			"pattern: %s, last checked byte in the sequence: %d",
			utf8_state2seq_description[st],
			utf8_state2byte_num[st]-1);
		return false;
	}
	return true;
#undef INVALID_SEQUENCE_ACTION
#undef INVALID_SEQUENCE_START_ACTION
}

bool fixup_utf8_inplace(std::string &s)
{
#define INVALID_SEQUENCE_ACTION() \
	modified = true; \
	bytes_to_trim = utf8_state2byte_num[st]-1; \
	pos-=bytes_to_trim; \
	s.erase(pos,bytes_to_trim); \
	pos--; \
	st = ST_COMPLETED; \
	continue;

#define INVALID_SEQUENCE_START_ACTION() \
	s.erase(pos,1); \
	pos--; \
	modified = true; \
	continue;

	size_t original_size = s.length();
	int bytes_to_trim;

	bool modified = false;
	utf8_fsm_state st = ST_COMPLETED;

	size_t pos = 0;
	for(;pos < s.length(); pos++) {
		unsigned char c = s[pos];
		switch(st) {
		DEFINE_SEQUENCE_CLASSIFIER;
		DEFINE_RANGE_VALIDATORS
		default:
			ERROR("fixup_utf8_inplace(): unknown state: %d. erase whole string",st);
			s.clear();
			return true;
		}
	}

	if(st!=ST_COMPLETED) {
		modified = true;
		bytes_to_trim = utf8_state2byte_num[st]-1;
		WARN("incompleted utf8 multibyte sequence. "
			"pattern: %s, last checked byte in the sequence: %d",
			utf8_state2seq_description[st],
			bytes_to_trim);
		pos-=bytes_to_trim;
		s.erase(pos,bytes_to_trim);
	}

	if(modified) {
		WARN("fixup_utf8_inplace(): erased %ld invalid bytes. "
			 "resulting size: %ld. "
			 "resulting string: \"%s\"",
			 original_size-s.length(),
			 s.length(),s.c_str());
	}
	return modified;
#undef INVALID_SEQUENCE_ACTION
#undef INVALID_SEQUENCE_START_ACTION
}

