/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* Copyright (c) 2002-2014 InMon Corp. Licensed under the terms of the InMon sFlow licence: */
/* http://www.inmon.com/technology/sflowlicense.txt */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_http.h>
#include <nginx.h>

#if (NGX_THREADS)
#include <ngx_thread.h>
#endif

#include "ngx_http_sflow_api.h"
#include "ngx_http_sflow_config.h"
#include "ngx_channel.h"

/*_________________---------------------------__________________
  _________________   unknown output defs     __________________
  -----------------___________________________------------------
*/

#define SFLOW_DURATION_UNKNOWN 0
#define SFLOW_TOKENS_UNKNOWN 0

/*_________________---------------------------__________________
  _________________  static vars (per worker) __________________
  -----------------___________________________------------------
  Some vars just have to be static so they can be accessed from
  all the right places in the cycle.
*/

/* for shared memory IPC */
typedef struct {
    ngx_pid_t pid;
    time_t lastActive;
    uint32_t drop_events;
    uint32_t sample_pool;
    SFLHTTP_counters http_counters;
} ngx_http_sflow_shm_worker_t;

typedef struct {
    SFWBConfigManager config_manager;
    ngx_atomic_int_t current_tick;
    ngx_atomic_int_t current_tick_done;
    SFLAgent *agent;
    SFLSampler *sampler;
    SFLPoller *poller;
    SFLReceiver *receiver;
    ngx_atomic_int_t max_process_slot;
    ngx_http_sflow_shm_worker_t workers[NGX_MAX_PROCESSES];
} ngx_http_sflow_shm_data_t;

static ngx_str_t ngx_http_sflow_shm_name = ngx_string("ngx_http_sflow_module_shm");
static ngx_shm_zone_t *ngx_http_sflow_shm_zone;

/* lowest numbered listen port */
static ngx_int_t ngx_http_sflow_lowest_port;

/* tick event */
static ngx_event_t sflow_tick;

/*_________________---------------------------__________________
  _________________ module state (per worker) __________________
  -----------------___________________________------------------
Here "SFWB" stands for "sFlow-Web". Used for code that is more
or less the same between here, mod-sflow for apache and the
sflow/haproxy branch too.  This is the structure we hang on
the nginx config object.
*/

typedef struct _SFWB {
    /* keep log ptr for callbacks */
    ngx_log_t *log;

#if (NGX_THREADS)
    ngx_mutex_t *mut;
#define SFWB_LOCK(_s) ngx_mutex_lock((_s)->mut)
#define SFWB_UNLOCK(_s) ngx_mutex_unlock((_s)->mut)
#define SFWB_INC_CTR(_c) ngx_atomic_fetch_add(&(_c), 1)
#define SFWB_COUNTDOWN(_c) (ngx_atomic_fetch_add(&(_c), -1) == 1)
#else
#define SFWB_LOCK(_s) /* no-op */
#define SFWB_UNLOCK(_s) /* no-op */
#define SFWB_INC_CTR(_c) (_c)++
#define SFWB_COUNTDOWN(_c) (--(_c) == 0)
#endif

    /* skip countdown is handled per-worker to reduce lock contention.
     * If all processes sample at 1:N it's the same as having only one
     * sampler at 1:N.  We still use a local lock if there are multiple
     * threads per worker,  but it seems more common to use multiple
     * worker processes and make each one single-threaded.
     */

    uint32_t sampling_rate;
    uint32_t random_seed;
    ngx_atomic_int_t sflow_skip;

    /* compiled nginx variable indices */
    ngx_int_t vidx_uri;
    ngx_int_t vidx_host;
    ngx_int_t vidx_referer;
    ngx_int_t vidx_useragent;
    ngx_int_t vidx_xff;
    ngx_int_t vidx_mimetype;
    ngx_int_t vidx_authuser;

} SFWB;

typedef struct {
    SFWB *sfwb;
} ngx_http_sflow_main_conf_t;

typedef struct {
    ngx_uint_t off;
} ngx_http_sflow_loc_conf_t;


/*_________________---------------------------__________________
  _________________      fn declarations      __________________
  -----------------___________________________------------------
*/

static ngx_int_t ngx_http_sflow_init(ngx_conf_t *cf);
static void ngx_http_sflow_tick(SFWB *sm, ngx_log_t *log);


/*_________________---------------------------__________________
  _________________   ngx config file         __________________
  -----------------___________________________------------------
*/

static char *
ngx_http_sflow_set_option(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_sflow_loc_conf_t *llcf = conf;
    ngx_str_t *value;

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "off") == 0) {
        llcf->off = 1;
        if (cf->args->nelts == 2) {
            return NGX_CONF_OK;
        }
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[2]);
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}


static void *
ngx_http_sflow_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_sflow_main_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_sflow_main_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    return conf;
}


static void *
ngx_http_sflow_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_sflow_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_sflow_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }
    return conf;
}


static char *
ngx_http_sflow_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_sflow_loc_conf_t *prev = parent;
    ngx_http_sflow_loc_conf_t *conf = child;

    if (conf->off) {
        return NGX_CONF_OK;
    }
    conf->off = prev->off;
    return NGX_CONF_OK;
}

/*_________________------------------------------__________________
  _________________ ngx_http_sflow_get_shm_pool  __________________
  -----------------______________________________------------------
*/
static ngx_slab_pool_t *
ngx_http_sflow_get_shm_pool() {
    if(ngx_http_sflow_shm_zone == NULL) {
        return NULL;
    }
    return (ngx_slab_pool_t *)ngx_http_sflow_shm_zone->shm.addr;
}

/*_________________------------------------------__________________
  _________________  ngx_http_sflow_get_shm_data __________________
  -----------------______________________________------------------
*/

static ngx_http_sflow_shm_data_t *
ngx_http_sflow_get_shm_data() {
    if(ngx_http_sflow_shm_zone == NULL) {
        return NULL;
    }
    return (ngx_http_sflow_shm_data_t *)ngx_http_sflow_shm_zone->data;
}

/*_________________---------------------------------__________________
  _________________  ngx_http_sflow_slab_alloc      __________________
  -----------------_________________________________------------------
*/

static size_t
ngx_http_sflow_slab_alloc_size(size_t bytes) {
    /* round up to pagesize, because smaller allocations
       were failing and returning NULL on openSUSE-12.2 32bit
    */
    return ngx_align(bytes, ngx_pagesize);
}

static void *
ngx_http_sflow_slab_alloc(ngx_slab_pool_t *pool, size_t bytes) {
    size_t adjusted = ngx_http_sflow_slab_alloc_size(bytes);
    void *ans = ngx_slab_alloc(pool, adjusted);
    if(ans == NULL && sflow_tick.log) {
        ngx_log_error(NGX_LOG_ERR, sflow_tick.log, 0, "ngx_slab_alloc(%d) failed: (errno=%d)", adjusted, errno);
    }
    return ans;
}
    
 
/*_________________------------------------------------__________________
  _________________  ngx_http_sflow_update_shm_slot    __________________
  -----------------____________________________________------------------
*/
static ngx_int_t
ngx_http_sflow_update_shm_slot(ngx_log_t *log)
{
    ngx_http_sflow_shm_data_t *shm_data;

    if((shm_data = ngx_http_sflow_get_shm_data()) == NULL) {
        return NGX_ERROR;
    }

    shm_data->workers[ngx_process_slot].pid = ngx_getpid();
    shm_data->workers[ngx_process_slot].lastActive = ngx_time();
    if(ngx_process_slot > shm_data->max_process_slot) {
        shm_data->max_process_slot = ngx_process_slot;
    }
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, log, 0,
                   "sflow: process %d wrote my pid (%d) into the shm zone",
                   ngx_process_slot, ngx_getpid());
    return NGX_OK;
}

/*_________________------------------------------__________________
  _________________  ngx_http_sflow_tick_handler __________________
  -----------------______________________________------------------
*/
static void
ngx_http_sflow_tick_handler(ngx_event_t *ev)
{
    SFWB *sfwb;
    if(ev->log) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ev->log, 0, "sflow: http sflow tick handler");
    }
    if(!ngx_exiting
       && (sfwb = (SFWB *)ev->data) != NULL) {
        SFWB_LOCK(cf->sfwb);
        ngx_http_sflow_tick(sfwb, ev->log);
        ngx_add_timer(ev, 1000);
        SFWB_UNLOCK(cf->sfwb);
    }
}

/*_________________----------------------------__________________
  _________________ ngx_http_sflow_init_worker __________________
  -----------------____________________________------------------
*/

static ngx_int_t
ngx_http_sflow_init_worker(ngx_cycle_t *cycle)
{
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, cycle->log, 0, "sflow: ngx_http_sflow_init_worker slot=%d", ngx_process_slot);

    /* populate worker slot in shared memory zone */
    ngx_http_sflow_update_shm_slot(cycle->log);

    /* schedule tick timer */
    sflow_tick.log = cycle->log;
    ngx_add_timer(&sflow_tick, 1000);
    return NGX_OK;
}

/*_________________---------------------------__________________
  _________________   ngx module registration __________________
  -----------------___________________________------------------
*/

static ngx_command_t ngx_http_sflow_commands[] = {

    { ngx_string("sflow"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
                        |NGX_HTTP_LMT_CONF|NGX_CONF_TAKE123,
      ngx_http_sflow_set_option,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_sflow_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_sflow_init,                   /* postconfiguration */
    ngx_http_sflow_create_main_conf,       /* create main configuration */
    NULL,                                  /* init main configuration */
    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */
    ngx_http_sflow_create_loc_conf,        /* create location configration */
    ngx_http_sflow_merge_loc_conf          /* merge location configration */
};


ngx_module_t  ngx_http_sflow_module = {
    NGX_MODULE_V1,
    &ngx_http_sflow_module_ctx,            /* module context */
    ngx_http_sflow_commands,               /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    ngx_http_sflow_init_worker,            /* init worker process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit worker process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

/*_________________---------------------------__________________
  _________________   sfwb_ipv4MappedAddress  __________________
  -----------------___________________________------------------
*/

#if (NGX_HAVE_INET6)
static bool_t
sfwb_ipv4MappedAddress(SFLIPv6 *ipv6addr, SFLIPv4 *ip4addr) {
    static char mapped_prefix[] = { 0,0,0,0,0,0,0,0,0,0,0xFF,0xFF };
    static char compat_prefix[] = { 0,0,0,0,0,0,0,0,0,0,0,0 };
    if(!memcmp(ipv6addr->addr, mapped_prefix, 12) ||
       !memcmp(ipv6addr->addr, compat_prefix, 12)) {
        memcpy(ip4addr, ipv6addr->addr + 12, 4);
        return true;
    }
    return false;
}
#endif

/*_________________----------------------------------__________________
  _________________ ngx_http_sflow_write_flow_sample __________________
  -----------------__________________________________------------------
*/

static void
ngx_http_sflow_write_flow_sample(SFL_FLOW_SAMPLE_TYPE *fs, ngx_log_t *log)
{
    ngx_slab_pool_t *shm_pool;
    ngx_http_sflow_shm_data_t *shm_data;

    if((shm_pool = ngx_http_sflow_get_shm_pool()) == NULL) {
        return;
    }
    if((shm_data = ngx_http_sflow_get_shm_data()) == NULL) {
        return;
    }

    ngx_shmtx_lock(&shm_pool->mutex);
    
    if(shm_data->sampler) {
        int s;
        /* Not sure we can trust the value of ngx_last_process here. So
         * use the max_process_slot number that we maintain ourselves.
         */
        for(s=0; s <= shm_data->max_process_slot; s++) {
            /* even if a process was active and the stopped, we still want
             * to include his (frozen) numbers in the overall counts.  So
             * we accept any non-zero value for lastActive:
             */
            if(shm_data->workers[s].lastActive) {
                fs->sample_pool += shm_data->workers[s].sample_pool;
                fs->drops += shm_data->workers[s].drop_events;
            }
        }
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0, "sflow: writeFlowSample");
        sfl_sampler_writeFlowSample(shm_data->sampler, fs);
    }
    ngx_shmtx_unlock(&shm_pool->mutex);
}

/*_________________-------------------------------------__________________
  _________________ ngx_http_sflow_write_counter_sample __________________
  -----------------_____________________________________------------------
*/

static void
ngx_http_sflow_write_counter_sample(SFL_COUNTERS_SAMPLE_TYPE *cs)
{
    ngx_slab_pool_t *shm_pool;
    ngx_http_sflow_shm_data_t *shm_data;

    if((shm_pool = ngx_http_sflow_get_shm_pool()) == NULL) {
        return;
    }
    if((shm_data = ngx_http_sflow_get_shm_data()) == NULL) {
        return;
    }

    ngx_shmtx_lock(&shm_pool->mutex);
    
    if(shm_data->poller) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, sflow_tick.log, 0, "sflow: writeCountersSample");
        sfl_poller_writeCountersSample(shm_data->poller, cs);
    }
    ngx_shmtx_unlock(&shm_pool->mutex);
}

/*_________________---------------------------__________________
  _________________   sfwb_sample_http        __________________
  -----------------___________________________------------------
*/

static void
sfwb_sample_http(ngx_connection_t *connection, SFLHTTP_method method, uint32_t proto_num, ngx_http_variable_value_t *uri, ngx_http_variable_value_t *host, ngx_http_variable_value_t *referrer, ngx_http_variable_value_t *useragent, ngx_http_variable_value_t *xff, ngx_http_variable_value_t *authuser, ngx_http_variable_value_t *mimetype, uint64_t req_bytes, uint64_t resp_bytes, uint32_t duration_uS, uint32_t status)
{
    
    SFL_FLOW_SAMPLE_TYPE fs;
    memset(&fs, 0, sizeof(fs));
        
    /* indicate that I am the server by setting the
       destination interface to 0x3FFFFFFF=="internal"
       and leaving the source interface as 0=="unknown" */
    fs.output = 0x3FFFFFFF;
        
    SFLFlow_sample_element httpElem;
    memset(&httpElem, 0, sizeof(httpElem));

    httpElem.tag = SFLFLOW_HTTP;
    httpElem.flowType.http.method = method;
    httpElem.flowType.http.protocol = proto_num;
    httpElem.flowType.http.uri.str = uri->data;
    httpElem.flowType.http.uri.len = uri->len;
    httpElem.flowType.http.host.str = host->data;
    httpElem.flowType.http.host.len = host->len;
    httpElem.flowType.http.referrer.str = referrer->data;
    httpElem.flowType.http.referrer.len = referrer->len;
    httpElem.flowType.http.useragent.str = useragent->data;
    httpElem.flowType.http.useragent.len = useragent->len;
    httpElem.flowType.http.xff.str = xff->data;
    httpElem.flowType.http.xff.len = xff->len;
    httpElem.flowType.http.authuser.str = authuser->data;
    httpElem.flowType.http.authuser.len = authuser->len;
    httpElem.flowType.http.mimetype.str = mimetype->data;
    httpElem.flowType.http.mimetype.len = mimetype->len;
    httpElem.flowType.http.req_bytes = req_bytes;
    httpElem.flowType.http.resp_bytes = resp_bytes;
    httpElem.flowType.http.uS = duration_uS;
    httpElem.flowType.http.status = status;
    SFLADD_ELEMENT(&fs, &httpElem);
    
    SFLFlow_sample_element socElem;
    memset(&socElem, 0, sizeof(socElem));
    
    if(connection) {
        /* add a socket structure */
        struct sockaddr_in *localsoc = (struct sockaddr_in *)connection->local_sockaddr;
        struct sockaddr_in *peersoc = (struct sockaddr_in *)connection->sockaddr;

        /* TODO: It looks like these fields may be accessible as variables that we can ask for
         * as indexed variables.  This fn should probably just accept the request as arg
         * and get all the vars from that.
         */

        if(localsoc && peersoc) {
            if(peersoc->sin_family == AF_INET) {
                socElem.tag = SFLFLOW_EX_SOCKET4;
                socElem.flowType.socket4.protocol = 6; /* TCP */
                memcpy(&socElem.flowType.socket4.local_ip.addr, &(localsoc->sin_addr), 4);
                memcpy(&socElem.flowType.socket4.remote_ip.addr, &(peersoc->sin_addr), 4);
                socElem.flowType.socket4.local_port = ntohs(localsoc->sin_port);
                socElem.flowType.socket4.remote_port = ntohs(peersoc->sin_port);
            }
#if (NGX_HAVE_INET6)
            else if(peersoc->sin_family == AF_INET6) {
                struct sockaddr_in6 *localsoc6 = (struct sockaddr_in6 *)connection->local_sockaddr;
                struct sockaddr_in6 *peersoc6 = (struct sockaddr_in6 *)connection->sockaddr;
                /* may still decide to export it as an IPv4 connection
                   if the addresses are really IPv4 addresses */
                SFLIPv4 local_ip4addr, remote_ip4addr;
                if(sfwb_ipv4MappedAddress((SFLIPv6 *)&(localsoc6->sin6_addr), &local_ip4addr) &&
                   sfwb_ipv4MappedAddress((SFLIPv6 *)&(peersoc6->sin6_addr), &remote_ip4addr)) {
                    socElem.tag = SFLFLOW_EX_SOCKET4;
                    socElem.flowType.socket4.protocol = 6; /* TCP */
                    socElem.flowType.socket4.local_ip.addr = local_ip4addr.addr;
                    socElem.flowType.socket4.remote_ip.addr = remote_ip4addr.addr;
                    socElem.flowType.socket4.local_port = ntohs(localsoc6->sin6_port);
                    socElem.flowType.socket4.remote_port = ntohs(peersoc6->sin6_port);
                }
                else {
                    socElem.tag = SFLFLOW_EX_SOCKET6;
                    socElem.flowType.socket6.protocol = 6; /* TCP */
                    memcpy(socElem.flowType.socket6.local_ip.addr, &(localsoc6->sin6_addr), 16);
                    memcpy(socElem.flowType.socket6.remote_ip.addr, &(peersoc6->sin6_addr), 16);
                    socElem.flowType.socket6.local_port = ntohs(localsoc6->sin6_port);
                    socElem.flowType.socket6.remote_port = ntohs(peersoc6->sin6_port);
                }
            }
#endif
            
            if(socElem.tag) {
                SFLADD_ELEMENT(&fs, &socElem);
            }
            else {
                /* something odd here - don't add the socElem. We can still send the sample below */
                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, connection->log, 0, "sflow: unexpected socket length or address family");
            }
        }
    }

    /* submit it to the shared-memory agent */
    ngx_http_sflow_write_flow_sample(&fs, connection->log);
}

/*_________________---------------------------__________________
  _________________  sflow agent callbacks    __________________
  -----------------___________________________------------------
*/

static void
sfwb_cb_error(void *magic, SFLAgent *agent, char *msg)
{
    /* the sflow_tick object has the log object for this worker */
    if(sflow_tick.log) {
        ngx_log_error(NGX_LOG_ERR, sflow_tick.log, 0, "sFlow agent error: %s", msg);
    }
}

static void
sfwb_cb_counters(void *magic, SFLPoller *poller, SFL_COUNTERS_SAMPLE_TYPE *cs)
{
    SFLCounters_sample_element httpElem;
    SFLCounters_sample_element parElem;
    uint32_t parent_ds_index;
    ngx_http_sflow_shm_data_t *shm_data;
    int s = 0;

    if((shm_data = ngx_http_sflow_get_shm_data()) == NULL) {
        return;
    }
    if(sfwb_config_polling_secs(&shm_data->config_manager)) {

        /* synthesize the counters from the per-worker structures in shared memory.
         * Don't worry about locking.  We are reporting monotonically-increasing
         * counters, so if there is a race this time and we miss an increment then it
         * will be included in the total next time.
         */
        memset(&httpElem, 0, sizeof(SFLCounters_sample_element));
        httpElem.tag = SFLCOUNTERS_HTTP;
        SFLHTTP_counters *totals = &httpElem.counterBlock.http;

        for(s=0; s <= shm_data->max_process_slot; s++) {
            /* even if a process was active and the stopped, we still want
             * to include his (frozen) numbers in the overall counts.  So
             * we accept any non-zero value for lastActive:
             */
            if(shm_data->workers[s].lastActive) {
                SFLHTTP_counters *ctrs = &shm_data->workers[s].http_counters;
                totals->method_head_count += ctrs->method_head_count;
                totals->method_get_count += ctrs->method_get_count;
                totals->method_put_count += ctrs->method_put_count;
                totals->method_post_count += ctrs->method_post_count;
                totals->method_delete_count += ctrs->method_delete_count;
                totals->method_connect_count += ctrs->method_connect_count;
                totals->method_option_count += ctrs->method_option_count;
                totals->method_trace_count += ctrs->method_trace_count;
                totals->method_other_count += ctrs->method_other_count;
                
                totals->status_1XX_count += ctrs->status_1XX_count;
                totals->status_2XX_count += ctrs->status_2XX_count;
                totals->status_3XX_count += ctrs->status_3XX_count;
                totals->status_4XX_count += ctrs->status_4XX_count;
                totals->status_5XX_count += ctrs->status_5XX_count;
                totals->status_other_count += ctrs->status_other_count;
            }
        }

        /* counters have now been accumulated here */
        SFLADD_ELEMENT(cs, &httpElem);

        parent_ds_index = sfwb_config_parent_ds_index(&shm_data->config_manager);
        if(parent_ds_index) {
            /* we learned the parent_ds_index from the config file, so add a parent structure too. */
            memset(&parElem, 0, sizeof(parElem));
            parElem.tag = SFLCOUNTERS_HOST_PAR;
            parElem.counterBlock.host_par.dsClass = SFL_DSCLASS_PHYSICAL_ENTITY;
            parElem.counterBlock.host_par.dsIndex = parent_ds_index;
            SFLADD_ELEMENT(cs, &parElem);
        }

        ngx_http_sflow_write_counter_sample(cs);
    }
}

static void
sfwb_cb_sendPkt(void *magic, SFLAgent *agent, SFLReceiver *receiver, u_char *pkt, uint32_t pktLen)
{
    ngx_http_sflow_shm_data_t *shm_data;
    if((shm_data = ngx_http_sflow_get_shm_data()) == NULL) {
        return;
    }
    sfwb_config_send_packet(&shm_data->config_manager, pkt, pktLen, sflow_tick.log);
}

/*_________________----------------------------------_______________
  _________________  ngx_http_sflow_add_random_skip  _______________
  -----------------__________________________________---------------
  return the new skip
*/

static int32_t
ngx_http_sflow_add_random_skip(SFWB *sm)
{
    sm->random_seed  = ((sm->random_seed * 32719) + 3) % 32749;
    ngx_atomic_t next_skip = (sm->random_seed % ((2 * sm->sampling_rate) - 1)) + 1;
#if (NGX_THREADS)
    ngx_atomic_int_t test_skip = ngx_atomic_fetch_add(&sm->sflow_skip, next_skip);
    return (test_skip + next_skip);
#else
    sm->sflow_skip = next_skip;
    return next_skip;
#endif
}

/*_________________---------------------------__________________
  _________________ lowest active listen port __________________
  -----------------___________________________------------------
*/

#ifndef DEFAULT_HTTP_PORT
#define DEFAULT_HTTP_PORT 80
#endif

static uint16_t
sfwb_lowestActiveListenPort()
{
    /* actually we already looked this up and saved it in ngx_http_sflow_lowest_port */
    return (ngx_http_sflow_lowest_port <= 0) ?  DEFAULT_HTTP_PORT : (u_int16_t)ngx_http_sflow_lowest_port;
}

/*_________________---------------------------__________________
  _________________       sfwb_changed        __________________
  -----------------___________________________------------------

  The config changed - set up the sFlow agent.
  the agent, sampler and poller should already
  be created in the shared-memory realm, so here
  we just have to drop in the agent-address,
  sampling-rate and polling-interval.
*/

static void
sfwb_changed(ngx_log_t *log)
{
    ngx_http_sflow_shm_data_t *shm_data;
    ngx_slab_pool_t *shm_pool;

    if((shm_data = ngx_http_sflow_get_shm_data()) == NULL) {
        return;
    }
    if((shm_pool = ngx_http_sflow_get_shm_pool()) == NULL) {
        return;
    }
    if(!sfwb_config_valid(&shm_data->config_manager)) {
        return;
    }

    ngx_shmtx_lock(&shm_pool->mutex);
    SFLAddress *agentIP = sfwb_config_agentIP(&shm_data->config_manager);
    if(agentIP) {
        memcpy(&shm_data->agent->myIP, agentIP, sizeof(SFLAddress));
        sfl_sampler_resetFlowSeqNo(shm_data->sampler);
        sfl_poller_resetCountersSeqNo(shm_data->poller);
        sfl_receiver_resetSampleCollector(shm_data->receiver);
    }
    sfl_poller_set_sFlowCpInterval(shm_data->poller, sfwb_config_polling_secs(&shm_data->config_manager));
    sfl_sampler_set_sFlowFsPacketSamplingRate(shm_data->sampler, sfwb_config_sampling_n(&shm_data->config_manager));

    ngx_shmtx_unlock(&shm_pool->mutex);
}

/*_________________---------------------------__________________
  _________________      1 second tick        __________________
  -----------------___________________________------------------
*/
        
static void
ngx_http_sflow_tick(SFWB *sm, ngx_log_t *log)
{
    ngx_http_sflow_shm_data_t *shm_data;
    
    if((shm_data= ngx_http_sflow_get_shm_data()) == NULL) {
        return;
    }

    /* all workers clock in */
    ngx_http_sflow_update_shm_slot(log);

    /* need to decide who is going to handle the tick this time */
    time_t now = ngx_time();
    time_t current_tick = shm_data->current_tick;
    if(now != current_tick 
       && current_tick == shm_data->current_tick_done) {
        /* I win the right to process the tick if I can
         * be the first to write in the new current_tick
         */
        if(ngx_atomic_cmp_set(&shm_data->current_tick, current_tick, now)) {
            /* Oh wow, I won. I'd like to thank my agent, my allocator... */
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, log, 0,
                           "sflow: tick won by process %d pid=%d",
                           ngx_process_slot, ngx_getpid());
            
            if(sfwb_config_tick(&shm_data->config_manager, log)) {
                /* the config changed - init/reinit the agent */
                sfwb_changed(log);
            }
            /* give the tick to the sFlow agent - may trigger a counters callback */
            sfl_agent_tick(shm_data->agent, now);

            /* and we we are all done we indicate it like this, so
             * that the next tick can only be processed after this
             * point.
             */
            shm_data->current_tick_done = now;
        }
    }

    /* since we are handling the sampling in the workers,  need to notice
     * if the shared sampling rate has changed and apply it: 
     */
    if(sm->sampling_rate != sfwb_config_sampling_n(&shm_data->config_manager)) {
        sm->sampling_rate = sfwb_config_sampling_n(&shm_data->config_manager);
        sm->sflow_skip = 0;
        ngx_http_sflow_add_random_skip(sm);
    }
}

/*_________________---------------------------__________________
  _________________  ngx_http_sflow_init_shm  __________________
  -----------------___________________________------------------
*/

static ngx_int_t
ngx_http_sflow_init_shm(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_slab_pool_t *shm_pool;
    ngx_http_sflow_shm_data_t *shm_data;
    SFLAddress emptyAgentIP;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, shm_zone->shm.log, 0, "sflow: ngx_http_sflow_init_shm()");

    if(data) {
        /* we are being reloaded.  Keep everything the same. */
        shm_zone->data = data;
        return NGX_OK;
    }

    /* Allocate from this space using the slab-allocator that has been
     * put in place for us at the beginning of this segment.
     */
    shm_pool = (ngx_slab_pool_t *)shm_zone->shm.addr;
    shm_data = shm_zone->data = ngx_http_sflow_slab_alloc(shm_pool, sizeof(ngx_http_sflow_shm_data_t));
    if(shm_data == NULL) {
        return NGX_ERROR;
    }

    /* initialize the agent with it's address, bootime, callbacks etc. */
    uint16_t servicePort = sfwb_lowestActiveListenPort();
    time_t now = ngx_time();
    memset(&emptyAgentIP, 0, sizeof(SFLAddress));
    shm_data->agent = (SFLAgent *)ngx_http_sflow_slab_alloc(shm_pool, sizeof(SFLAgent));
    if(shm_data->agent == NULL) {
        return NGX_ERROR;
    }
    sfl_agent_init(shm_data->agent,
                   &emptyAgentIP,
                   servicePort, /* subAgentId */
                   now,
                   now,
                   NULL, /* magic ptr */
                   sfwb_cb_error,
                   sfwb_cb_sendPkt);
    
    /* add a receiver */
    shm_data->receiver = (SFLReceiver *)ngx_http_sflow_slab_alloc(shm_pool, sizeof(SFLReceiver));
    if(shm_data->receiver == NULL) {
        return NGX_ERROR;
    }
    sfl_agent_addReceiver(shm_data->agent, shm_data->receiver);
    sfl_receiver_set_sFlowRcvrOwner(shm_data->receiver, "httpd sFlow Probe");
    sfl_receiver_set_sFlowRcvrTimeout(shm_data->receiver, 0xFFFFFFFF);
    
    /* no need to configure the receiver further, because we are */
    /* using the sendPkt callback to handle the forwarding ourselves. */
    
    /* add a <logicalEntity> datasource to represent this application instance */
    SFLDataSource_instance dsi;
    /* ds_class = <logicalEntity>, ds_index = <lowest service port>, ds_instance = 0 */
    SFL_DS_SET(dsi, SFL_DSCLASS_LOGICAL_ENTITY, servicePort, 0);
    
    /* add a poller for the counters */
    shm_data->poller = (SFLPoller *)ngx_http_sflow_slab_alloc(shm_pool, sizeof(SFLPoller));
    if(shm_data->poller == NULL) {
        return NGX_ERROR;
    }
    sfl_agent_addPoller(shm_data->agent, &dsi, NULL, sfwb_cb_counters, shm_data->poller);
    sfl_poller_set_sFlowCpInterval(shm_data->poller, 0 /* start with polling=0 */);
    sfl_poller_set_sFlowCpReceiver(shm_data->poller, 1 /* receiver index == 1 */);
    
    /* add a sampler for the sampled operations */
    shm_data->sampler = (SFLSampler *)ngx_http_sflow_slab_alloc(shm_pool, sizeof(SFLSampler));
    if(shm_data->sampler == NULL) {
        return NGX_ERROR;
    }
    sfl_agent_addSampler(shm_data->agent, &dsi, shm_data->sampler);
    sfl_sampler_set_sFlowFsPacketSamplingRate(shm_data->sampler, 0 /* start with sampling=0 */);
    sfl_sampler_set_sFlowFsReceiver(shm_data->sampler, 1 /* receiver index == 1 */);

    /* initialze the config_manager */
    sfwb_config_init(&shm_data->config_manager, shm_zone->shm.log);

    return NGX_OK;
}

/*_________________---------------------------__________________
  _________________      sfwb_init            __________________
  -----------------___________________________------------------
*/

static void
sfwb_init(SFWB *sm, ngx_conf_t *cf)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cf->log, 0, "sflow: sfwb_init()");

#if (NGX_THREADS)
    /* a mutex to lock the sFlow agent when taking a sample (only needed if there
     * is more that one worker thread - right now it seems like threads are not even
     * an option in the configure script)
     */
    sm->mut = ngx_mutex_init(cf->log, 0);
#endif

    /* look up some vars by name and cache the index numbers -- see ngx_http_variables.c */
    ngx_str_t str_uri = ngx_string("request_uri"); /* the "unparsed" variant */
    ngx_str_t str_host = ngx_string("http_host");
    ngx_str_t str_referer = ngx_string("http_referer");
    ngx_str_t str_useragent = ngx_string("http_user_agent");
    ngx_str_t str_xff = ngx_string("http_x_forwarded_for");
    ngx_str_t str_mimetype = ngx_string("content_type");
    ngx_str_t str_authuser = ngx_string("remote_user");
    sm->vidx_uri = ngx_http_get_variable_index(cf, &str_uri);
    sm->vidx_host = ngx_http_get_variable_index(cf, &str_host);
    sm->vidx_referer = ngx_http_get_variable_index(cf, &str_referer);
    sm->vidx_useragent = ngx_http_get_variable_index(cf, &str_useragent);
    sm->vidx_xff = ngx_http_get_variable_index(cf, &str_xff);
    sm->vidx_mimetype = ngx_http_get_variable_index(cf, &str_mimetype);
    sm->vidx_authuser = ngx_http_get_variable_index(cf, &str_authuser);

    /* the random number generation is scoped to the worker level
     * so we can use the PID as the seed.
     */
    sm->random_seed = ngx_getpid();
}

/*_________________---------------------------__________________
  _________________   method numbers          __________________
  -----------------___________________________------------------
*/

static SFLHTTP_method
sfwb_methodNumberLookup(int method)
{
    /* defititions from src/http/ngx_http_request.h */
    switch(method) {
    case NGX_HTTP_GET: return SFHTTP_GET;
    case NGX_HTTP_PUT: return SFHTTP_PUT;
    case NGX_HTTP_POST: return SFHTTP_POST;
    case NGX_HTTP_DELETE: return SFHTTP_DELETE;
    /* case NGX_HTTP_CONNECT: return SFHTTP_CONNECT; */
    case NGX_HTTP_OPTIONS: return SFHTTP_OPTIONS;
    case NGX_HTTP_TRACE: return SFHTTP_TRACE;
    default: return SFHTTP_OTHER;
    }
}

/*_________________---------------------------__________________
  _________________  ngx_http_sflow_handler   __________________
  -----------------___________________________------------------
*/

static ngx_int_t
ngx_http_sflow_handler(ngx_http_request_t *r)
{
    ngx_http_sflow_loc_conf_t  *lcf;
    ngx_http_sflow_main_conf_t  *cf;
    ngx_http_sflow_shm_data_t *shm_data;

    if((shm_data = ngx_http_sflow_get_shm_data()) == NULL) {
        return NGX_OK;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "sflow: http sflow handler");

    cf = ngx_http_get_module_main_conf(r, ngx_http_sflow_module);

    /* sFlow may be turned off in the config file just for this location */
    lcf = ngx_http_get_module_loc_conf(r, ngx_http_sflow_module);
    if (lcf->off) {
        return NGX_OK;
    }
    
    SFLHTTP_method method = r->header_only ? SFHTTP_HEAD : sfwb_methodNumberLookup(r->method);
    uint32_t status = 0;
    if (r->err_status) status = r->err_status;
    else if (r->headers_out.status) status = r->headers_out.status;

    /* update my worker-scoped shared-memory counter block */
    ngx_http_sflow_shm_worker_t *shm_worker_data = &shm_data->workers[ngx_process_slot];
    SFLHTTP_counters *ctrs = &shm_worker_data->http_counters;

    switch(method) {
    case SFHTTP_HEAD: SFWB_INC_CTR(ctrs->method_head_count); break;
    case SFHTTP_GET: SFWB_INC_CTR(ctrs->method_get_count); break;
    case SFHTTP_PUT: SFWB_INC_CTR(ctrs->method_put_count); break;
    case SFHTTP_POST: SFWB_INC_CTR(ctrs->method_post_count); break;
    case SFHTTP_DELETE: SFWB_INC_CTR(ctrs->method_delete_count); break;
    case SFHTTP_CONNECT: SFWB_INC_CTR(ctrs->method_connect_count); break;
    case SFHTTP_OPTIONS: SFWB_INC_CTR(ctrs->method_option_count); break;
    case SFHTTP_TRACE: SFWB_INC_CTR(ctrs->method_trace_count); break;
    default: SFWB_INC_CTR(ctrs->method_other_count); break;
    }

    if(status < 100) SFWB_INC_CTR(ctrs->status_other_count);
    else if(status < 200) SFWB_INC_CTR(ctrs->status_1XX_count);
    else if(status < 300) SFWB_INC_CTR(ctrs->status_2XX_count);
    else if(status < 400) SFWB_INC_CTR(ctrs->status_3XX_count);
    else if(status < 500) SFWB_INC_CTR(ctrs->status_4XX_count);
    else if(status < 600) SFWB_INC_CTR(ctrs->status_5XX_count);    
    else SFWB_INC_CTR(ctrs->status_other_count);

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "sflow: http sflow handler worker=%d, N=%d, countdown=%d",
                   ngx_process_slot,
                   sfwb_config_sampling_n(&shm_data->config_manager),
                   cf->sfwb->sflow_skip);

    if(sfwb_config_sampling_n(&shm_data->config_manager) == 0) {
        /* not configured for sampling yet */
        return NGX_OK;
    }

    /* increment the all-important sample_pool */
    SFWB_INC_CTR(shm_worker_data->sample_pool);

    if(SFWB_COUNTDOWN(cf->sfwb->sflow_skip)) {
        /* skip just went from 1 to 0, so take sample */

        ngx_time_t *tp = ngx_timeofday();
        ngx_msec_int_t ms = (ngx_msec_int_t)
            ((tp->sec - r->start_sec) * 1000 + (tp->msec - r->start_msec));
        ms = ngx_max(ms, 0);
        
        sfwb_sample_http(r->connection,
                         method,
                         r->http_version,
                         ngx_http_get_indexed_variable(r, cf->sfwb->vidx_uri),
                         ngx_http_get_indexed_variable(r, cf->sfwb->vidx_host),
                         ngx_http_get_indexed_variable(r, cf->sfwb->vidx_referer),
                         ngx_http_get_indexed_variable(r, cf->sfwb->vidx_useragent),
                         ngx_http_get_indexed_variable(r, cf->sfwb->vidx_xff),
                         ngx_http_get_indexed_variable(r, cf->sfwb->vidx_authuser),
                         ngx_http_get_indexed_variable(r, cf->sfwb->vidx_mimetype),
                         0, /* not sure if nginx tracks anything like "bytes-received-last-request" */
                         ngx_max(0, (r->connection->sent - r->header_size))/* body-bytes to match apache */,
                         (ms * 1000)/*duration_uS*/,
                         status);
        
        /* the skip counter could be something like -1 or -2 now if other threads were decrementing
           it while we were taking this sample. So rather than just set the new skip count and ignore those
           other decrements, we do an atomic add.
           In the extreme case where the new random skip is small then we might not get the skip back above 0
           with this add,  and so the new skip would effectively be ~ 2^32.  Just to make sure that doesn't
           happen we loop until the skip is above 0 (and count any extra adds as drop-events). */
        /* one advantage of this approach is that we only have to generate a new random number when we
           take a sample,  and because we have the mutex locked we don't need to make the random number
           seed a per-thread variable. */

        SFWB_LOCK(cf->sfwb);
        while(ngx_http_sflow_add_random_skip(cf->sfwb) <= 0) {
            /* doesn't have to be perfect so just use ++ */
            shm_worker_data->drop_events++;
        }
        SFWB_UNLOCK(cf->sfwb);
    }

    return NGX_OK;
}

/*_________________---------------------------__________________
  _________________  ngx_http_sflow_init      __________________
  -----------------___________________________------------------
*/

static ngx_int_t
ngx_http_sflow_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt *h;
    ngx_http_sflow_main_conf_t *smcf;
    ngx_http_core_main_conf_t *cmcf;
    uint32_t ii;
    int32_t lowestPort;
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cf->log, 0, "sflow: ngx_http_sflow_init()");

    smcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_sflow_module);
    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    *h = ngx_http_sflow_handler;

    /* get the lowest numbered listen port while we have cmcf */
    lowestPort = -1;
    if(cmcf->ports) {
        ngx_http_conf_port_t *port = (ngx_http_conf_port_t *)cmcf->ports->elts;
        for (ii = 0; ii < cmcf->ports->nelts; ii++) {
            in_port_t pt = ntohs(port[ii].port);
            if(lowestPort == -1 || 
               (int)pt < lowestPort) lowestPort = (int)pt;
        }
    }
    ngx_http_sflow_lowest_port = lowestPort;

    /* init shared memory - make sure there is plenty of headroom for the slab-allocator */
    size_t shm_size = \
        ngx_http_sflow_slab_alloc_size(sizeof(ngx_http_sflow_shm_data_t)) + \
        ngx_http_sflow_slab_alloc_size(sizeof(SFLAgent)) +              \
        ngx_http_sflow_slab_alloc_size(sizeof(SFLSampler)) +            \
        ngx_http_sflow_slab_alloc_size(sizeof(SFLPoller)) +             \
        ngx_http_sflow_slab_alloc_size(sizeof(SFLReceiver));
    shm_size = (ngx_pagesize * 2) + ngx_align(shm_size, ngx_pagesize);
    /* tag the named memory segment with my module pointer to avoid unexpected aliasing */
    ngx_http_sflow_shm_zone = ngx_shared_memory_add(cf, &ngx_http_sflow_shm_name, shm_size, &ngx_http_sflow_module);
    ngx_http_sflow_shm_zone->init = ngx_http_sflow_init_shm;

    /* init the per-worker state */
    smcf->sfwb = ngx_pcalloc(cf->pool, sizeof(SFWB));
    sfwb_init(smcf->sfwb, cf);

    /* init tick event - will be scheduled on worker-init */
    sflow_tick.handler = ngx_http_sflow_tick_handler;
    sflow_tick.data = (void *)smcf->sfwb;

    return NGX_OK;
}
