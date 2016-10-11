#include "errno.h"

#include "log.h"
#include "AmConfig.h"
#include "AmPlugIn.h"
#include "AmSdp.h"
#include "AmAudio.h"
#include "AmUtils.h"

#include <fstream>
#include <iostream>

using namespace std;

int main(int argc, char *argv[])
{
	int ret = EXIT_FAILURE,rc;

	amci_codec_t *codec = NULL;
	amci_payload_t *payload = NULL;
	unsigned char *out,*in;
	long int in_size, out_size;
	amci_codec_fmt_info_t fmt_i[4];
	timeval start,end,diff;
	long h_codec = -1;


	if(argc<3){
		printf("%s payload_name file_to_decode\n"
			   "\tdecode frames in file using choosen codec plugin",argv[0]);
		return EXIT_FAILURE;
	}

	string plugin = argv[1];
	string path = argv[2];

	if(AmConfig::readConfiguration()){
		ERROR("Errors occured while reading configuration file: exiting.");
		return EXIT_FAILURE;
	}

	AmPlugIn &am_plugin = *AmPlugIn::instance();

	INFO("Loading audio plug-in %s\n",plugin.c_str());
	am_plugin.init();
	if(am_plugin.load(AmConfig::PlugInPath, plugin)){
		ERROR("Can't load plugins. exiting.");
		return EXIT_FAILURE;
	}

	vector<SdpPayload> pl_vec;
	am_plugin.getPayloads(pl_vec);

	if(pl_vec.size()<2){ //first payload is telephone_event
		ERROR("'%s'' is not audio plugin. exiting",plugin.c_str());
		return EXIT_FAILURE;
	}

	for(vector<SdpPayload>::const_iterator i = pl_vec.begin();i!=pl_vec.end();++i){
		const SdpPayload &p = *i;
		if(p.encoding_name!="telephone-event"){
			payload = am_plugin.payload(p.payload_type);
		}
	}
	if(!payload){
		ERROR("can't find loaded payload");
		return EXIT_FAILURE;
	}
	codec = am_plugin.codec(payload->codec_id);
	if(!codec){
		ERROR("can't load codec with id %d for payload %s",
			  payload->codec_id,payload->name);
		return EXIT_FAILURE;
	}

	INFO("will use payload %s with codec_id %d, payload_id: %d",
		 payload->name,payload->codec_id,payload->payload_id);

	if(codec->init){
		fmt_i[0].id = 0;
		h_codec = (*codec->init)("", fmt_i);
		int i=0;
		while (fmt_i[i].id) {
			switch (fmt_i[i].id) {
			case AMCI_FMT_FRAME_LENGTH : {
				INFO("frame_length = %d",fmt_i[i].value);
			} break;
			case AMCI_FMT_FRAME_SIZE: {
				INFO("frame_size = %d",fmt_i[i].value);
			} break;
			case AMCI_FMT_ENCODED_FRAME_SIZE: {
				INFO("encoded_frame_size = %d",fmt_i[i].value);
			} break;
			default: {
			  WARN("Unknown codec format descriptor: %d\n", fmt_i[i].id);
			} break;
			}
			i++;
		}
	}

	if(!codec->decode){
		ERROR("codec for payload %s. doesn't have decode() func",payload->name);
		return EXIT_FAILURE;
	}
	if(!codec->bytes2samples && !codec->frames2samples){
		ERROR("codec for payload %s. doesn't have bytes2samples() or frames2samples() func",payload->name);
		return EXIT_FAILURE;
	}

	FILE *f = fopen(path.c_str(),"rb");
	if(f==NULL){
		ERROR("can't open file: %s",strerror(errno));
		return EXIT_FAILURE;
	}

	fseek(f,0,SEEK_END);
	in_size = ftell(f);
	rewind(f);

	in = new unsigned char[in_size];
	if(!in){
		ERROR("can't allocate memory for input buffer");
		goto fail_close_f;
	}

	rc=fread(in,1,in_size,f);
	if(rc!=in_size){
		ERROR("fread() = %d",rc);
		goto fail_free_in;
	}
	INFO("%d bytes were gained from file for decoding",rc);

	//if(codec->b)
	if(codec->frames2samples){
		out_size = PCM16_S2B((*codec->frames2samples)(h_codec,in,in_size));
	} else {
		out_size = PCM16_S2B((*codec->bytes2samples)(h_codec,in_size));
	}
	//out_size = PCM16_S2B((*codec->bytes2samples)(h_codec,in_size));
	INFO("alleged output buffer size: %ld",out_size);
	out = new unsigned char [out_size];
	if(!out){
		ERROR("can't allocate memory for output buffer");
		goto fail_free_in;
	}

	gettimeofday(&start,NULL);
	rc = (*codec->decode)(out,in,in_size,1,8e3,h_codec);
	gettimeofday(&end,NULL);

	if(codec->destroy)
		(*codec->destroy)(h_codec);

	if(rc < 0){
		ERROR("decode() = %d",rc);
		goto fail_cleanup;
	}

	timersub(&end,&start,&diff);
	INFO("decode() = %d. took: %f seconds",rc,timeval2double(diff));

	ret = EXIT_SUCCESS;

fail_cleanup:
	delete[] out;
fail_free_in:
	delete[] in;
fail_close_f:
	fclose(f);

	return ret;
}
