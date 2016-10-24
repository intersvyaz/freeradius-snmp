#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

enum {
  RLM_SNMP_GET,
  RLM_SNMP_SET
};

typedef struct rlm_snmp_t {
  struct {
    const char *action;
    vp_tmpl_t *server;
    vp_tmpl_t *community;
    vp_tmpl_t *oid;
    vp_tmpl_t *value;
    const char *value_type;
    vp_tmpl_t *output_attr;
    uint16_t port;
    int timeout;
    int retries;
  } cfg;

  int action;
} rlm_snmp_t;

static const CONF_PARSER module_config[] = {
    {"action", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_NOT_EMPTY, rlm_snmp_t, cfg.action), NULL},
    {"server", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_TMPL | PW_TYPE_NOT_EMPTY, rlm_snmp_t, cfg.server), NULL},
    {"community",
     FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_TMPL | PW_TYPE_REQUIRED | PW_TYPE_SECRET, rlm_snmp_t, cfg.community),
     NULL},
    {"oid", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_TMPL | PW_TYPE_NOT_EMPTY, rlm_snmp_t, cfg.oid), NULL},
    {"value", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_TMPL, rlm_snmp_t, cfg.value), NULL},
    {"value_type", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_NOT_EMPTY, rlm_snmp_t, cfg.value_type), "="},
    {"output_attr", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_TMPL, rlm_snmp_t, cfg.output_attr), NULL},
    {"port", FR_CONF_OFFSET(PW_TYPE_SHORT | PW_TYPE_NOT_EMPTY, rlm_snmp_t, cfg.port), "162"},
    {"timeout", FR_CONF_OFFSET(PW_TYPE_SIGNED | PW_TYPE_NOT_EMPTY, rlm_snmp_t, cfg.timeout), "-1"},
    {"retries", FR_CONF_OFFSET(PW_TYPE_SIGNED | PW_TYPE_NOT_EMPTY, rlm_snmp_t, cfg.retries), "-1"},
    CONF_PARSER_TERMINATOR
};

/**
 * Instanitate module.
 * @param[in] conf Module config.
 * @param[in] instance MOdule instance.
 * @return Zero on success.
 */
static int mod_instantiate(CONF_SECTION *conf, void *instance) {
  struct rlm_snmp_t *inst = instance;

  if (!strcasecmp(inst->cfg.action, "get")) {
    inst->action = RLM_SNMP_GET;
    if (!inst->cfg.output_attr || (inst->cfg.output_attr->type != TMPL_TYPE_ATTR)) {
      cf_log_err_cs(conf, "invalid option 'output_attr'");
    }
  } else if (!strcasecmp(inst->cfg.action, "set")) {
    inst->action = RLM_SNMP_SET;

    if ((strlen(inst->cfg.value_type) != 1) || !strchr("=iutaosxdbUIFD", inst->cfg.value_type[0])) {
      cf_log_err_cs(conf, "invalid option 'value_type'");
      return -1;
    }
  } else {
    cf_log_err_cs(conf, "invalid option 'action', use 'get' or 'set'");
    return -1;
  }

  if (inst->cfg.timeout != -1) {
    inst->cfg.timeout *= 1000;
  }

  init_snmp("rlm_snmp");
  // disable extra quotes for snprint_value
  netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICK_PRINT, 1);

  return 0;
}

/**
 * Detach module.
 * @param[in] instance Module instance.
 * @return Zero on success.
 */
static int mod_detach(void *instance) {
  struct rlm_snmp_t *inst = instance;
  (void) inst;
  // do not call snmp_shutdown as other instances can still work.
  return 0;
}

/**
 * Main module procedure.
 * @param[in] instance Module instance.
 * @param[in] request Radius request.
 * @return
 */
static rlm_rcode_t mod_proc(void *instance, REQUEST *request) {
  struct rlm_snmp_t *inst = instance;
  void *sessp = NULL;
  netsnmp_pdu *response = NULL;
  rlm_rcode_t code = RLM_MODULE_FAIL;

  char *peername = NULL, *community = NULL, *oidstr = NULL;

  if (tmpl_aexpand(request, &peername, request, inst->cfg.server, NULL, NULL) < 0) {
    RERROR("failed to substitute attributes for server '%s'", inst->cfg.server->name);
    goto end;
  }
  if (tmpl_aexpand(request, &community, request, inst->cfg.community, NULL, NULL) < 0) {
    RERROR("failed to substitute attributes for community '<secret>'");
    goto end;
  }
  if (tmpl_aexpand(request, &oidstr, request, inst->cfg.oid, NULL, NULL) < 0) {
    RERROR("failed to substitute attributes for oid '%s'", inst->cfg.oid->name);
    goto end;
  }

  oid anOID[MAX_OID_LEN];
  size_t anOID_len = MAX_OID_LEN;
  if (!snmp_parse_oid(oidstr, anOID, &anOID_len)) {
    // XXX: can't use snmp_errno as it not thread safe
    RERROR("failed to parse oid %s", oidstr);
    goto end;
  }

  netsnmp_session session;
  snmp_sess_init(&session);
  session.version = SNMP_VERSION_2c;
  session.peername = peername;
  session.community = (u_char *) community;
  session.community_len = strlen(community);
  session.remote_port = inst->cfg.port;
  session.timeout = inst->cfg.timeout;
  session.retries = inst->cfg.retries;

  sessp = snmp_sess_open(&session);
  if (!sessp) {
    char *error_str = NULL;
    snmp_error(&session, NULL, NULL, &error_str);
    RERROR("snmp_sess_open failed: %s", error_str);
    if (error_str) free(error_str);
    goto end;
  }

  if (RLM_SNMP_GET == inst->action) {
    struct snmp_pdu *pdu = snmp_pdu_create(SNMP_MSG_GET);
    snmp_add_null_var(pdu, anOID, anOID_len);

    if (snmp_sess_synch_response(sessp, pdu, &response) != STAT_SUCCESS) {
      char *error_str = NULL;
      snmp_sess_error(sessp, NULL, NULL, &error_str);
      RERROR("snmp_get failed: %s", error_str);
      if (error_str) free(error_str);
      goto end;
    }

    if (!response->variables
        || (response->variables->type == SNMP_NOSUCHOBJECT)
        || (response->variables->type == SNMP_NOSUCHINSTANCE)
        || (response->variables->type == SNMP_ENDOFMIBVIEW)) {
      code = RLM_MODULE_NOTFOUND;
      goto end;
    }

    char value[MAX_STRING_LEN] = {0};
    int value_len = 0;
    // do not use snprint_value when length is zero!
    if (response->variables->val_len) {
      value_len = snprint_value(value, sizeof(value), anOID, anOID_len, response->variables);
    }
    RDEBUG2("set %s = '%s'", inst->cfg.output_attr->name, value);

    VALUE_PAIR *vp = NULL;
    if (tmpl_find_vp(&vp, request, inst->cfg.output_attr) != 0) {
      RADIUS_PACKET *packet = radius_packet(request, inst->cfg.output_attr->tmpl_list);
      VALUE_PAIR **vps = radius_list(request, inst->cfg.output_attr->tmpl_list);
      vp = fr_pair_afrom_da(packet, inst->cfg.output_attr->tmpl_da);
      fr_pair_add(vps, vp);
    }

    fr_pair_value_from_str(vp, value, (size_t) value_len);
    code = RLM_MODULE_UPDATED;
  } else {
    char *value = NULL;
    if (tmpl_aexpand(request, &value, request, inst->cfg.value, NULL, NULL) < 0) {
      RERROR("failed to substitute attributes for value '%s'", inst->cfg.value->name);
      goto end;
    }

    struct snmp_pdu *pdu = snmp_pdu_create(SNMP_MSG_SET);
    int ret = snmp_add_var(pdu, anOID, anOID_len, inst->cfg.value_type[0], value);
    if (ret != SNMPERR_SUCCESS) {
      RERROR("failed to create snmp_set request: %s", snmp_errstring(ret));
      snmp_free_pdu(pdu);
      goto end;
    }

    if (snmp_sess_synch_response(sessp, pdu, &response) != STAT_SUCCESS) {
      char *error_str = NULL;
      snmp_sess_error(sessp, NULL, NULL, &error_str);
      RERROR("snmp_set failed: %s", error_str);
      if (error_str) free(error_str);
      goto end;
    }

    RDEBUG("wrote %s@%s = %s", peername, oidstr, value);
    code = RLM_MODULE_OK;
  }

  end:
  if (response) snmp_free_pdu(response);
  if (sessp) snmp_sess_close(sessp);
  return code;
}

// globally exported name
extern module_t rlm_snmp;
module_t rlm_snmp = {
    .magic = RLM_MODULE_INIT,
    .name = "snmp",
    .type = RLM_TYPE_THREAD_SAFE | RLM_TYPE_HUP_SAFE,
    .inst_size = sizeof(rlm_snmp_t),
    .config = module_config,
    .bootstrap = NULL,
    .instantiate = mod_instantiate,
    .detach = mod_detach,
    .methods = {
        [MOD_AUTHENTICATE] = mod_proc,
        [MOD_AUTHORIZE] = mod_proc,
        [MOD_PREACCT] = mod_proc,
        [MOD_ACCOUNTING] = mod_proc,
        [MOD_SESSION] = NULL,
        [MOD_PRE_PROXY] = mod_proc,
        [MOD_POST_PROXY] = mod_proc,
        [MOD_POST_AUTH] = mod_proc,
#ifdef WITH_COA
        [MOD_RECV_COA] = mod_proc,
        [MOD_SEND_COA] = mod_proc,
#endif
    },
};
