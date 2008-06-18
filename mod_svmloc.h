#ifndef __MOD_SVMLOC_H__
#define __MOD_SVMLOC_H__

static const int MAX_SIZE = 16384;

/* Representation of an SVM */
typedef struct {
  SVM* pSVM;
  char* SVM_handler;
  char* model_filename;
  char* freqpattern_filename;
  void* nextSVM;
} SVM_Obj_holder;

/* server config structure */
typedef struct {
  SVM_Obj_holder* SVMList;
} mod_SVMLoc_svr_cfg;


static int SVMLoc_handler(request_rec* r);
static int mod_SVMLoc_hook_post_config(apr_pool_t *pconf, apr_pool_t *plog,
                                       apr_pool_t *ptemp, server_rec *s);
static void mod_SVMLoc_hooks(apr_pool_t* pool);
static void mod_SVMLoc_remove_SVM(SVM_Obj_holder** parent_SVM_Obj, SVM_Obj_holder* SVM_Obj);

static void* mod_SVMLoc_svr_conf(apr_pool_t* pool, server_rec* s);
static SVM_Obj_holder* mod_SVMLoc_fetch_SVM(server_rec* s, apr_pool_t* pool,  const char* SVM, int make);
static const char* modSVMLoc_set_handler(cmd_parms* cmd, void* cfg, const char* HandlerName);
static const char* modSVMLoc_set_model_filename(cmd_parms* cmd, void* cfg, const char* HandlerName, const char* modelFilename);
static const char* modSVMLoc_set_freqpattern_filename(cmd_parms* cmd, void* cfg, const char* HandlerName, const char* freqpatternFilename);

static apr_hash_t *parse_form_from_string(request_rec *r, char *args);
static apr_hash_t* parse_form_from_GET(request_rec *r);
static int parse_form_from_POST(request_rec* r, apr_hash_t** form);

#endif
