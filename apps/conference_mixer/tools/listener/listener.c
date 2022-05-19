#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <getopt.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <arpa/inet.h>
/* Use the newer ALSA API */
#define ALSA_PCM_NEW_HW_PARAMS_API

#include <alsa/asoundlib.h>
#include <linux/types.h>
//#include <stdint.h>

#include <pulse/simple.h>
#include <pulse/error.h>
#define BUFSIZE 1024

#define PCM_DEVICE "default"
#define CHANNELS 1
#define MAX_EPOLL_EVENTS 265
#define RECV_BUF 8192

void PANIC(char* msg);
#define PANIC(msg) { perror(msg); exit (0); }

static const char	*bindto = "0.0.0.0";
static volatile int     term_event = 0;

static unsigned short  port = 5002;

static unsigned char buf[RECV_BUF];
static int          epollfd,
                    sock_fd;

static snd_pcm_t *pcm_handle = NULL;

static int use_pulse = 0;
static pa_simple *pulse_handle = NULL;
static pa_sample_spec ss = {
    .format = PA_SAMPLE_S16LE,
    //.rate = 44100,
    //.rate = h->sample_rate,
    .channels = CHANNELS
};

struct sems_hdr {
    __u64   id;
    __u32   sample_rate;
    __u32   length;
} __attribute__((packed));


static struct option long_options[] = {
    { "--bind",     required_argument,  0,  'b' },
    { "--port",     required_argument,  0,  'p' },
    { "--pulse",    required_argument,  0,  'x'  },
    { 0,            0,                  0,   0  }
};


static void sig_term(int sign)
{
    term_event = 1;
}


static void init_signals(void)
{
    struct sigaction act = {};

    act.sa_handler = SIG_IGN;
    sigaction(SIGIO,   &act, NULL);
    sigaction(SIGURG,  &act, NULL);
    sigaction(SIGPIPE, &act, NULL);
    sigaction(SIGALRM, &act, NULL);

    act.sa_handler = &sig_term;
    sigaction(SIGINT,  &act, NULL);
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGQUIT, &act, NULL);
    sigaction(SIGHUP,  &act, NULL);
    sigaction(SIGUSR1, &act, NULL);
    sigaction(SIGUSR2, &act, NULL);

}


static void print_usage(char *argv[])
{
    printf("Usage: %s [args]\nArguments:\n"
        "\t-p, --port <port>      - port listening to\n"
        "\t-b, --bind <addr>      - addr bind to\n\n"
        "\t-x, --pulse            - use pulseaudio sound backend\n\n",
        argv[0]);
}

static int socket_init(unsigned short port)
{
    int fd;
    if ((fd = socket( AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0)) == -1)
        PANIC("socket(): %m");

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) == -1)
        PANIC("setsockopt(SO_REUSEADDR): %m");

#ifdef SO_REUSEPORT // (since Linux 3.9)
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &(int){1}, sizeof(int)) == -1)
        PANIC("setsockopt(SO_REUSEPORT): %m");
#endif


    static struct sockaddr_in addr = {};

    addr.sin_family = AF_INET;
    //addr.sin_addr.s_addr= htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    if (inet_aton(bindto, &addr.sin_addr) == 0)
        PANIC("inet_aton(): %m");

    if (bind(fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) == -1)
        PANIC("bind(): %m");

    return fd;
}


static void register_socket2epoll(int fd)
{
    struct epoll_event event;

    event.data.fd = fd;
    event.events = EPOLLIN; //| EPOLLET;

    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &event) < 0 )
        PANIC("epoll_ctl(): %m");

}


static snd_pcm_t *init_hw(unsigned int samplerate, int fr)
{
    snd_pcm_t *pcm_handle;
    snd_pcm_hw_params_t *params;
    snd_pcm_uframes_t frames = fr;
    int dir;

    fprintf(stderr,"Try init to samplerate %d frames %ld\n", samplerate, frames);

    /* Open the PCM device in playback mode */
    snd_pcm_open(&pcm_handle, PCM_DEVICE, SND_PCM_STREAM_PLAYBACK, 0);

    /* Allocate parameters object and fill it with default values*/
    snd_pcm_hw_params_alloca(&params);
    snd_pcm_hw_params_any(pcm_handle, params);
    /* Set parameters */
    snd_pcm_hw_params_set_access(pcm_handle, params, SND_PCM_ACCESS_RW_INTERLEAVED);
    snd_pcm_hw_params_set_format(pcm_handle, params, SND_PCM_FORMAT_S16_LE); // SND_PCM_FORMAT_S16 SND_PCM_FORMAT_S16_LE SND_PCM_FORMAT_FLOAT
    snd_pcm_hw_params_set_channels(pcm_handle, params, CHANNELS);
    snd_pcm_hw_params_set_rate_near(pcm_handle, params, &samplerate, &dir);
    snd_pcm_hw_params_set_period_size_near(pcm_handle, params, &frames, &dir);

    /* Write the parameters to the driver */
      int rc = snd_pcm_hw_params(pcm_handle, params);
      if (rc < 0) {
        fprintf(stderr, "unable to set hw parameters: %s\n", snd_strerror(rc));
        exit(1);
      }


    /* Allocate buffer to hold single period */
    snd_pcm_hw_params_get_period_size(params, &frames, &dir);

    fprintf(stderr,"# frames in a period: %ld\n", frames);
    return pcm_handle;
}




static void handler(struct epoll_event *event);


int main(int argc, char **argv)
{
    int long_index = 0, opt = 0;

    while ((opt = getopt_long(argc, argv,"p:b:x", long_options, &long_index )) != -1) {
        switch (opt) {
            case 'p' :  port = atoi(optarg);
                        break;
            case 'b' :  bindto = optarg;
                        break;
            case 'x' :  use_pulse = 1;
                        break;
            default  :  print_usage(argv);
                        exit(EXIT_FAILURE);
        }
    }

    printf("use %s sound backend\n",
           use_pulse ? "pulseaudio" : "alsa");

    init_signals();

    epollfd = epoll_create1(0);
    sock_fd = socket_init(port);
    register_socket2epoll(sock_fd);

    fprintf(stderr,"Bind to %s:%d\n", bindto, port);

    do {
        struct epoll_event events[MAX_EPOLL_EVENTS];
        int     nfds;

        nfds = epoll_wait(epollfd, (struct epoll_event*)&events, MAX_EPOLL_EVENTS, -1);

        if ( nfds < 0 ) {
            if ( errno != EINTR )
                fprintf(stderr,"epoll_wait(): %m");
            continue;
        }


        for (int i = 0; i < nfds; i++) {
            struct epoll_event *event = &events[i];

            handler(event);

        }

    } while (!term_event);

    if (pcm_handle) {
        snd_pcm_drain(pcm_handle);
        snd_pcm_close(pcm_handle);
    }

    if(pulse_handle) {
        pa_simple_free(pulse_handle);
    }

    return 0;
}


static double timeval2double(const struct timeval *tv)
{
    return tv->tv_sec + tv->tv_usec/(double)1e6;
}


static void handler(struct epoll_event *event)
{
    static int counter = 0;
    static struct timeval tv0,tv1;

    struct sockaddr src_addr;
    socklen_t       addrlen = sizeof(struct sockaddr);
    struct sems_hdr *h = (struct sems_hdr *)&buf;

    if (!(event->events & EPOLLIN))
        return;


    ssize_t ret = recvfrom(sock_fd, buf, sizeof(buf), 0, &src_addr, &addrlen);

    if (ret <= sizeof(struct sems_hdr)) {
        fprintf(stderr,"recvfrom(): %m\n");
        return;
    }

    void *data = buf + sizeof(struct sems_hdr);
    int frames = h->length/2;

    if(!use_pulse) {
        int pcmrc;

        if (!pcm_handle) {
            // fprintf(stderr,"%ld %lld %d %d\n", ret, h->id, h->sample_rate, h->length);
            printf("init alsa hw with sample rate: %u\n",h->sample_rate);
            pcm_handle = init_hw(h->sample_rate, frames);
            // prevent Underrun
            snd_pcm_writei(pcm_handle, data, frames);
        }

        pcmrc = snd_pcm_writei(pcm_handle, data, frames);

        if (pcmrc == -EPIPE) {
            fprintf(stderr, "E");
            //fprintf(stderr, "Underrun!\n");
            //snd_pcm_prepare(pcm_handle);
        } else if (pcmrc < 0) {
            fprintf(stderr, "Error writing to PCM device: %s\n", snd_strerror(pcmrc));
        } else if (pcmrc != frames) {
            fprintf(stderr,"PCM write difffers from PCM read.\n");
        }

        gettimeofday(&tv1, NULL);

        double diff = timeval2double(&tv1) - timeval2double(&tv0);
        memcpy(&tv0, &tv1, sizeof(struct timeval));

        fprintf(stderr,"%d frames %d %.2f\n",counter, frames, diff*1000);

        ++counter;

    } else {
        int error;

        if(!pulse_handle) {
            ss.rate = h->sample_rate;

            printf("init pulseaudio stream with sample rate: %u\n",ss.rate);

            if(!(pulse_handle = pa_simple_new(
                NULL, "listener",
                PA_STREAM_PLAYBACK, NULL,
                "playback",
                &ss, NULL, NULL, &error)))
            {
                    fprintf(stderr, __FILE__": pa_simple_new() failed: %s\n", pa_strerror(error));
                    return;
            }
        }

        if(pa_simple_write(pulse_handle, data, h->length, &error) < 0) {
            fprintf(stderr, __FILE__": pa_simple_write() failed: %s\n", pa_strerror(error));
        }
    }
}
