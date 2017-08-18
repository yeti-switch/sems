#include "errno.h"

#include "log.h"
#include "AmConfig.h"
#include "AmPlugIn.h"
#include "AmSdp.h"
#include "AmAudio.h"
#include "AmUtils.h"
#include "AmAudioFile.h"

#include <fstream>
#include <iostream>
#include <algorithm>

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

	AmAudioFile out_file;

	if(argc<5){
		printf("%s plugin_name payload_name file_to_decode out_file\n"
			   "\tdecode frames in file using choosen codec plugin\n",argv[0]);
		return EXIT_FAILURE;
	}

	string plugin = argv[1];
	string payload_name = argv[2];
	string path = argv[3];
	char *out_file_path = argv[4];

	if(AmConfig::readConfiguration()){
		ERROR("Errors occured while reading configuration file: exiting.");
		return EXIT_FAILURE;
	}

	AmPlugIn &am_plugin = *AmPlugIn::instance();

	am_plugin.init();

	INFO("Loading audio plug-in wav");
	if(am_plugin.load(AmConfig::PlugInPath, "wav")){
		ERROR("Can't load plugins. exiting.");
		return EXIT_FAILURE;
	}
	INFO("Loading audio plug-in %s\n",plugin.c_str());

	transform(payload_name.begin(), payload_name.end(), payload_name.begin(), ::tolower);
	if(payload_name=="pcmu" || payload_name=="pcma") {
		INFO("%s is built-in codec. skip plugin loading",plugin.c_str());
	} else {
		if(am_plugin.load(AmConfig::PlugInPath, plugin)){
			ERROR("Can't load plugins. exiting.");
			return EXIT_FAILURE;
		}
	}

	vector<SdpPayload> pl_vec;
	am_plugin.getPayloads(pl_vec);

	for(auto const &p: pl_vec) {
		string e = p.encoding_name;
		transform(e.begin(), e.end(), e.begin(), ::tolower);
		if(e==payload_name) {
			payload = am_plugin.payload(p.payload_type);
		}
	}
	if(!payload){
		ERROR("can't find payload");
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
		DBG("use frames2samples to get output buffer size");
		out_size = PCM16_S2B((*codec->frames2samples)(h_codec,in,in_size));
	} else {
		DBG("use bytes2samples to get output buffer size");
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

	if(0!=out_file.open(out_file_path,AmAudioFile::Write)) {
		ERROR("couldn't init AmAudioFile instance for output file");
			return EXIT_FAILURE;		goto fail_cleanup;
	}
	if(0!=out_file.put(0,out,payload->sample_rate,PCM16_B2S(ret))) {
		ERROR("couldn't init AmAudioFile instance for output file");
		goto fail_cleanup;
	}

	ret = EXIT_SUCCESS;

fail_cleanup:
	delete[] out;
fail_free_in:
	delete[] in;
fail_close_f:
	fclose(f);

	return ret;
}
