/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* Copyright (c) 2002-2010 InMon Corp. Licensed under the terms of the InMon sFlow licence: */
/* http://www.inmon.com/technology/sflowlicense.txt */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>

#if (NGX_THREADS)
#include <ngx_thread.h>
#endif

#include "ngx_http_sflow_api.h"
#include "ngx_http_sflow_config.h"

/*_________________---------------------------__________________
  _________________   unknown output defs     __________________
  -----------------___________________________------------------
*/

#define SFLOW_DURATION_UNKNOWN 0
#define SFLOW_TOKENS_UNKNOWN 0

/*_________________---------------------------__________________
  _________________   structure definitions   __________________
  -----------------___________________________------------------
*/

typedef struct _SFWB {
    /* memory pool to clear on a reconfig */
    ngx_pool_t *masterPool;

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

    /* delegate acquiring the sflow config */
    SFWBConfigManager *config_manager;

    /* sFlow agent */
    SFLAgent *agent;
    SFLReceiver *receiver;
    SFLSampler *sampler;
    SFLPoller *poller;

    /* keep track of the current second */
    time_t currentTime;

    /* skip countdown */
    ngx_atomic_int_t sflow_skip;

    /* the http counters */
    SFLCounters_sample_element http_counters;

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

#define SFWB_POOL_SIZ 10000

/*_________________---------------------------__________________
  _________________      fn declarations      __________________
  -----------------___________________________------------------
*/

static ngx_int_t ngx_http_sflow_init(ngx_conf_t *cf);


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

/*_________________---------------------------__________________
  _________________   ngx module registration __________________
  -----------------___________________________------------------
*/

static ngx_command_t  ngx_http_sflow_commands[] = {

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
    ngx_http_sflow_init,                     /* postconfiguration */

    ngx_http_sflow_create_main_conf,         /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_sflow_create_loc_conf,          /* create location configration */
    ngx_http_sflow_merge_loc_conf            /* merge location configration */
};


ngx_module_t  ngx_http_sflow_module = {
    NGX_MODULE_V1,
    &ngx_http_sflow_module_ctx,              /* module context */
    ngx_http_sflow_commands,                 /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

/*_________________---------------------------__________________
  _________________   ipv4MappedAddress       __________________
  -----------------___________________________------------------
*/

#if (NGX_HAVE_INET6)

static bool_t ipv4MappedAddress(SFLIPv6 *ipv6addr, SFLIPv4 *ip4addr) {
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

/*_________________---------------------------__________________
  _________________   sfwb_sample_http        __________________
  -----------------___________________________------------------
*/

static void sfwb_sample_http(SFLSampler *sampler, ngx_connection_t *connection, SFLHTTP_method method, uint32_t proto_num, ngx_http_variable_value_t *uri, ngx_http_variable_value_t *host, ngx_http_variable_value_t *referrer, ngx_http_variable_value_t *useragent, ngx_http_variable_value_t *xff, ngx_http_variable_value_t *authuser, ngx_http_variable_value_t *mimetype, uint64_t req_bytes, uint64_t resp_bytes, uint32_t duration_uS, uint32_t status)
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
                if(ipv4MappedAddress((SFLIPv6 *)&(localsoc6->sin6_addr), &local_ip4addr) &&
                   ipv4MappedAddress((SFLIPv6 *)&(peersoc6->sin6_addr), &remote_ip4addr)) {
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
                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, connection->log, 0, "unexpected socket length or address family");
            }
        }
    }
    
    sfl_sampler_writeFlowSample(sampler, &fs);
}

/*_________________---------------------------__________________
  _________________  sflow agent callbacks    __________________
  -----------------___________________________------------------
*/

static void *sfwb_cb_alloc(void *magic, SFLAgent *agent, size_t bytes)
{
    SFWB *sm = (SFWB *)magic;
    return ngx_pcalloc(sm->masterPool, bytes);
}

static int sfwb_cb_free(void *magic, SFLAgent *agent, void *obj)
{
    /* do nothing - we'll free the whole pool when we are ready */
    return 0;
}

static void sfwb_cb_error(void *magic, SFLAgent *agent, char *msg)
{
    SFWB *sm = (SFWB *)magic;
    ngx_log_error(NGX_LOG_ERR, sm->log, 0, "sFlow agent error: %s", msg);
}

static void sfwb_cb_counters(void *magic, SFLPoller *poller, SFL_COUNTERS_SAMPLE_TYPE *cs)
{
    SFWB *sm = (SFWB *)poller->magic;
    SFLCounters_sample_element parElem;
    uint32_t parent_ds_index;

    if(sfwb_config_polling_secs(sm->config_manager, sm->log)) {
        /* counters have been accumulated here */
        SFLADD_ELEMENT(cs, &sm->http_counters);

        parent_ds_index = sfwb_config_parent_ds_index(sm->config_manager, sm->log);
        if(parent_ds_index) {
            /* we learned the parent_ds_index from the config file, so add a parent structure too. */
            memset(&parElem, 0, sizeof(parElem));
            parElem.tag = SFLCOUNTERS_HOST_PAR;
            parElem.counterBlock.host_par.dsClass = SFL_DSCLASS_PHYSICAL_ENTITY;
            parElem.counterBlock.host_par.dsIndex = parent_ds_index;
            SFLADD_ELEMENT(cs, &parElem);
        }

        sfl_poller_writeCountersSample(poller, cs);
    }
}

static void sfwb_cb_sendPkt(void *magic, SFLAgent *agent, SFLReceiver *receiver, u_char *pkt, uint32_t pktLen)
{
    SFWB *sm = (SFWB *)magic;
    if(sm->config_manager) sfwb_config_send_packet(sm->config_manager, pkt, pktLen, sm->log);
}

/*_________________----------------------------------_______________
  _________________  ngx_http_sflow_add_random_skip  _______________
  -----------------__________________________________---------------
  return false if adding the next skip count did not bring the skip
  count back above 0 (only an issue in multithreaded deployment)
*/

static int32_t ngx_http_sflow_add_random_skip(SFWB *sm)
{
    ngx_atomic_t next_skip = sfl_sampler_next_skip(sm->sampler);
#if (NGX_THREADS)
    ngx_atomic_int_t test_skip = ngx_atomic_fetch_add(&sm->sflow_skip, next_skip);
    return (test_skip + next_skip);
#else
    sm->sflow_skip = next_skip;
    return next_skip;
#endif
}

/*_________________---------------------------__________________
  _________________       sfwb_changed        __________________
  -----------------___________________________------------------

The config changed - build/rebuild the sFlow agent
*/

static void sfwb_changed(SFWB *sm, ngx_log_t *log)
{
    if(!sfwb_config_valid(sm->config_manager)) {
        return;
    }

    /* create or re-create the agent */
    if(sm->agent) {
        sfl_agent_release(sm->agent);
        ngx_reset_pool(sm->masterPool);
    }
    
    sm->agent = (SFLAgent *)ngx_pcalloc(sm->masterPool, sizeof(SFLAgent));
    
    /* initialize the agent with it's address, bootime, callbacks etc. */
    sfl_agent_init(sm->agent,
                   sfwb_config_agentIP(sm->config_manager, log),
                   0, /* subAgentId */
                   sm->currentTime,
                   sm->currentTime,
                   sm,
                   sfwb_cb_alloc,
                   sfwb_cb_free,
                   sfwb_cb_error,
                   sfwb_cb_sendPkt);
    
    /* add a receiver */
    sm->receiver = sfl_agent_addReceiver(sm->agent);
    sfl_receiver_set_sFlowRcvrOwner(sm->receiver, "httpd sFlow Probe");
    sfl_receiver_set_sFlowRcvrTimeout(sm->receiver, 0xFFFFFFFF);
    
    /* no need to configure the receiver further, because we are */
    /* using the sendPkt callback to handle the forwarding ourselves. */
    
    /* add a <logicalEntity> datasource to represent this application instance */
    SFLDataSource_instance dsi;
    /* ds_class = <logicalEntity>, ds_index = 65538, ds_instance = 0 */
    /* $$$ should learn the ds_index from the config file */
    SFL_DS_SET(dsi, SFL_DSCLASS_LOGICAL_ENTITY, 65538, 0);
    
    /* add a poller for the counters */
    sm->poller = sfl_agent_addPoller(sm->agent, &dsi, sm, sfwb_cb_counters);
    sfl_poller_set_sFlowCpInterval(sm->poller, sfwb_config_polling_secs(sm->config_manager, log));
    sfl_poller_set_sFlowCpReceiver(sm->poller, 1 /* receiver index == 1 */);
    
    /* add a sampler for the sampled operations */
    sm->sampler = sfl_agent_addSampler(sm->agent, &dsi);
    sfl_sampler_set_sFlowFsPacketSamplingRate(sm->sampler, sfwb_config_sampling_n(sm->config_manager, log));
    sfl_sampler_set_sFlowFsReceiver(sm->sampler, 1 /* receiver index == 1 */);
    
    /* we're going to handle the skip countdown ourselves, so initialize it here */
    sm->sflow_skip = 0;
    ngx_http_sflow_add_random_skip(sm);
}

/*_________________---------------------------__________________
  _________________      1 second tick        __________________
  -----------------___________________________------------------
*/
        
static void sfwb_tick(SFWB *sm, ngx_log_t *log) {
    if(sm->config_manager) {
        if(sfwb_config_tick(sm->config_manager, log)) {
            /* the config changed - init/reinit the agent */
            sfwb_changed(sm, log);
        }
    }
    if(sm->agent) {
        sfl_agent_tick(sm->agent, sm->currentTime);
    }
}

/*_________________---------------------------__________________
  _________________      sfwb_init            __________________
  -----------------___________________________------------------
*/

static void sfwb_init(SFWB *sm, ngx_conf_t *cf)
{
    /* keep a pointer for logging in callbacks - seems to be done like this... */
    sm->log = &cf->cycle->new_log;

    /* a pool to use for the agent so we can recycle the memory easily on a config change */
    sm->masterPool = ngx_create_pool(SFWB_POOL_SIZ, cf->log);

#if (NGX_THREADS)
    /* a mutex to lock the sFlow agent when taking a sample (only needed if there
       is more that one worker thread - right now it seems like threads are not even
       an option in the configure script) */
    sm->mut = ngx_mutex_init(cf->log, 0);
#endif

    /* create and initialze the config_manager */
    sm->config_manager = ngx_pcalloc(cf->pool, sizeof(SFWBConfigManager));
    sfwb_config_init(sm->config_manager, cf->log);

    /* initialize the counter block */
    sm->http_counters.tag = SFLCOUNTERS_HTTP;

    /* look up some vars by name and cache the index numbers -- see ngx_http_variables.c */
    ngx_str_t str_uri = ngx_string("request_uri"); // the "unparsed" variant
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

}

/*_________________---------------------------__________________
  _________________   method numbers          __________________
  -----------------___________________________------------------
*/

static SFLHTTP_method sfwb_methodNumberLookup(int method)
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

ngx_int_t
ngx_http_sflow_handler(ngx_http_request_t *r)
{
    ngx_http_sflow_loc_conf_t  *lcf;
    ngx_http_sflow_main_conf_t  *cf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http sflow handler");

    cf = ngx_http_get_module_main_conf(r, ngx_http_sflow_module);

    /* approximate a 1-second tick - this assumes that we have constant activity. It may be
       better to run a separate thread just to do this reliably and conform to the sFlow standard
       even when nothing is happening.
       Alternatively - it looks like we might be able to ask for timer events from the engine. $$$
    */

    if(ngx_time() != cf->sfwb->currentTime) {
        SFWB_LOCK(cf->sfwb);
        /* repeat the test now that we have the mutex,  in case two threads saw the second rollover */
        if(ngx_time() != cf->sfwb->currentTime) {
            cf->sfwb->currentTime = ngx_time();
            sfwb_tick(cf->sfwb, r->connection->log);
        }
        SFWB_UNLOCK(cf->sfwb);
    }

    /* sFlow may be turned off in the config file just for this location */
    lcf = ngx_http_get_module_loc_conf(r, ngx_http_sflow_module);
    if (lcf->off) {
        return NGX_OK;
    }
    
    SFLHTTP_method method = r->header_only ? SFHTTP_HEAD : sfwb_methodNumberLookup(r->method);
    uint32_t status = 0;
    if (r->err_status) status = r->err_status;
    else if (r->headers_out.status) status = r->headers_out.status;
    SFLHTTP_counters *ctrs = &cf->sfwb->http_counters.counterBlock.http;
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

    if(sfwb_config_sampling_n(cf->sfwb->config_manager, r->connection->log) == 0) {
        /* not configured for sampling yet */
        return NGX_OK;
    }

    /* increment the all-important sample_pool */
    SFWB_INC_CTR(cf->sfwb->sampler->samplePool);

    if(SFWB_COUNTDOWN(cf->sfwb->sflow_skip)) {
        /* skip just went from 1 to 0, so take sample */

        SFWB_LOCK(cf->sfwb);

        ngx_time_t *tp = ngx_timeofday();
        ngx_msec_int_t ms = (ngx_msec_int_t)
            ((tp->sec - r->start_sec) * 1000 + (tp->msec - r->start_msec));
        ms = ngx_max(ms, 0);
        
        
        sfwb_sample_http(cf->sfwb->sampler,
                         r->connection,
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
                         ngx_max(0, (r->connection->sent - r->header_size))/* body-bytes to match apach e*/,
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
        while(ngx_http_sflow_add_random_skip(cf->sfwb) <= 0) {
            cf->sfwb->sampler->dropEvents++;
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
    ngx_http_handler_pt        *h;
    ngx_http_sflow_main_conf_t   *smcf;
    ngx_http_core_main_conf_t  *cmcf;

    smcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_sflow_module);
    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    *h = ngx_http_sflow_handler;


    smcf->sfwb = ngx_pcalloc(cf->pool, sizeof(SFWB));
    sfwb_init(smcf->sfwb, cf);

    return NGX_OK;
}
