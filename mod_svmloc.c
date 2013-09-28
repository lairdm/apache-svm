/* SVMLoc module
 *
 * Module to load LibSVM modules for PSORTb and classify
 * protein sequences.
 */

#include <httpd.h>
#include <http_protocol.h>
#include <http_config.h>
#include <http_log.h>
#include <apr_strings.h>
#include <apr_hash.h>
#include "binding.h"
#include "mod_svmloc.h"

/* Hook our handler into Apache at startup */
static void mod_SVMLoc_hooks(apr_pool_t* pool) {
  ap_hook_handler(SVMLoc_handler, NULL, NULL, APR_HOOK_MIDDLE) ;

  ap_hook_post_config(mod_SVMLoc_hook_post_config,
		      NULL, NULL, APR_HOOK_FIRST);
}

static void* mod_SVMLoc_svr_conf(apr_pool_t* pool, server_rec* s) {
  mod_SVMLoc_svr_cfg* svr = apr_pcalloc(pool, sizeof(mod_SVMLoc_svr_cfg));
  svr->SVMList = apr_pcalloc(pool, sizeof(SVM_Obj_holder));
  svr->SVMList->nextSVM = NULL;
  return svr;
}

static const command_rec mod_SVMLoc_cmds[] = {
  AP_INIT_TAKE1("SVMHandler", modSVMLoc_set_handler, NULL, RSRC_CONF,
		"Set Handler name for SVMLoc"),
  AP_INIT_TAKE2("SVMModel", modSVMLoc_set_model_filename, NULL, RSRC_CONF,
		"Set the model filename for SVMLoc"),
  AP_INIT_TAKE2("SVMFreqPattern", modSVMLoc_set_freqpattern_filename, NULL, RSRC_CONF,
		"Set the frequent patterns filename for SVMLoc"),
  { NULL }
};

module AP_MODULE_DECLARE_DATA svmloc_module = {
  STANDARD20_MODULE_STUFF,
  NULL,
  NULL,
  mod_SVMLoc_svr_conf,
  NULL,
  mod_SVMLoc_cmds,
  mod_SVMLoc_hooks
} ;


static int SVMLoc_handler(request_rec* r) {
  apr_hash_t *formdata = NULL;
  int rv = OK;
  SVM_Obj_holder* SVM_Obj = NULL;
  mod_SVMLoc_svr_cfg* svr = NULL;
  SVM* pSVM = NULL;
  int results;

  if ( !r->handler || strcmp(r->handler, "svmloc") ) {
    return DECLINED ;   /* none of our business */
  } 

  if ( (r->method_number != M_GET) && (r->method_number != M_POST) ) {
    return HTTP_METHOD_NOT_ALLOWED ;  /* Reject other methods */
  }

  svr
    = ap_get_module_config(r->server->module_config, &svmloc_module);
  if(svr == NULL) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
		  "Error (svr) is null, it shouldn't be!");
    return HTTP_INTERNAL_SERVER_ERROR;
  }

  SVM_Obj = svr->SVMList;
  if(SVM_Obj == NULL) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
		  "Error (SVM_Obj) is null, it shouldn't be!");
    return HTTP_INTERNAL_SERVER_ERROR;
  }

  /* Display the form data */
  if(r->method_number == M_GET) {
    formdata = parse_form_from_GET(r);
  }
  else if(r->method_number == M_POST) {
    const char* ctype = apr_table_get(r->headers_in, "Content-Type");
    if(ctype && (strcasecmp(ctype, 
			    "application/x-www-form-urlencoded")
		 == 0)) {
      rv = parse_form_from_POST(r, &formdata);
    }
  } else {
    ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
		  "Error, no data given to module, where's your sequence?");
    return HTTP_INTERNAL_SERVER_ERROR;
  }

  ap_set_content_type(r, "text/plain;charset=ascii") ;
  /*  ap_rputs(
	   "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01//EN\">\n", r) ;
    ap_rputs(
	   "<html><head><title>SVMLoc</title></head>", r) ;
	   ap_rputs("<body>", r) ;*/

  if(rv != OK) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
		  "Error, reading form data");
    return HTTP_INTERNAL_SERVER_ERROR;
  }
  else if(formdata == NULL) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
		  "Error, no form data found");
    return OK;
  } else {
    apr_hash_t *SVMs = NULL;
    apr_hash_index_t *index;
    SVM_Obj_holder* tSVM_Obj;
    char *key;
    apr_ssize_t klen;
    char *seq;
    char *val;
    const char *delim = "&";
    char *last;
    unsigned int SVM_count;

    val = apr_hash_get(formdata, "Module", APR_HASH_KEY_STRING);
    if(val == NULL) {
      ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
		    "Error, no SVM modules specified!");
      return OK;
    }

    SVMs = apr_hash_make(r->pool);

    for(key = apr_strtok(val, delim, &last); key != NULL;
	key = apr_strtok(NULL, delim, &last)) {

      tSVM_Obj = mod_SVMLoc_fetch_SVM(r->server, NULL, key, 0);
      if(tSVM_Obj != NULL) {
#ifdef DEBUG
	ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                      "Stashing SVM of type %s", key);
	if(tSVM_Obj->pSVM == NULL) {
	  ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
			"Error, pSVM component is NULL!");
	}
#endif
	apr_hash_set(SVMs, key, APR_HASH_KEY_STRING, tSVM_Obj->pSVM);
      } else {
	ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
		      "Error, can not find SVM of type %s", key);
      }
    }

    seq = apr_hash_get(formdata, "Seq", APR_HASH_KEY_STRING);
    if(seq == NULL) {
      ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
		    "Error, no sequence specified!");
      return OK;
    }

#ifdef DEBUG
    ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
		  "Sequences to be tested: %s", seq);

    SVM_count = apr_hash_count(SVMs);
    ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                  "SVMs to be run: %d", SVM_count);
#endif

    for(index = apr_hash_first(r->pool, SVMs); index != NULL;
	index = apr_hash_next(index)) {

      apr_hash_this(index, (const void**)&key, &klen, (void**)&pSVM);

#ifdef DEBUG
      ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
		    "About to run SVM: %s", key);
#endif

      if(pSVM != NULL) {
	results = SVMClassify(pSVM, seq);
	ap_rprintf(r, "%s: %d\n", key, results);
#ifdef DEBUG
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                      "SVM successful: %s: %d", key, results);
#endif
      } else {
	ap_rprintf(r, "%s: ERROR", key);
#ifdef DEBUG
	ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
		      "Error running SVM: %s", key);
#endif	
      }
    }
   
  }

  /*  ap_rputs("</body></html>", r) ;*/
  return OK ;
}

/* Add error reporting?  "Could not load model" etc */

static int mod_SVMLoc_hook_post_config(apr_pool_t *pconf, apr_pool_t *plog,
				       apr_pool_t *ptemp, server_rec *s) {

  SVM_Obj_holder* SVM_Obj;
  SVM_Obj_holder** prev_SVM_Obj;
  mod_SVMLoc_svr_cfg* svr
    = ap_get_module_config(s->module_config, &svmloc_module);

#ifdef DEBUG
  ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
	       "Beginning to initialize SVMs");
#endif
 
  SVM_Obj = svr->SVMList;
  prev_SVM_Obj = &(svr->SVMList);

  while(SVM_Obj->nextSVM != NULL) {
    SVM_Obj->pSVM = createSVM(0, 2, 3, 0, 0, 1, 0.5, 0.1);
    if(SVM_Obj->pSVM == NULL) {
      ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
		   "Error creating SVM, removing SVM");
      mod_SVMLoc_remove_SVM(prev_SVM_Obj, SVM_Obj);
      }

    if(! loadSVMModel(SVM_Obj->pSVM, SVM_Obj->model_filename)) {
      ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                   "Error loading model %s, removing SVM", SVM_Obj->model_filename);
      mod_SVMLoc_remove_SVM(prev_SVM_Obj, SVM_Obj);
      return 1;
    }

    if(! loadSVMFreqPattern(SVM_Obj->pSVM, SVM_Obj->freqpattern_filename)) {
      ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                   "Error loading freq patterns %s, removing SVM", SVM_Obj->freqpattern_filename);
      mod_SVMLoc_remove_SVM(prev_SVM_Obj, SVM_Obj);
    }

    if(SVM_Obj->pSVM == NULL) {
      ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                   "Error pSVM component is NULL!");
    }

#ifdef DEBUG
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
		 "Finished initializing SVM %s", SVM_Obj->SVM_handler);
#endif

    prev_SVM_Obj = (SVM_Obj_holder**)&SVM_Obj->nextSVM;
    SVM_Obj = (SVM_Obj_holder*)SVM_Obj->nextSVM;
  }

  return 0;
}

static void mod_SVMLoc_remove_SVM(SVM_Obj_holder** parent_SVM_Obj, SVM_Obj_holder* SVM_Obj) {
  SVM_Obj_holder* temp_SVM_Obj;

  if((SVM_Obj == NULL) || (SVM_Obj->nextSVM == NULL)) {
    return;
  }

  temp_SVM_Obj = SVM_Obj;

  *parent_SVM_Obj = SVM_Obj->nextSVM;

  /* Figure out how to safely deallocate temp_SVM_Obj here */
}


static SVM_Obj_holder* mod_SVMLoc_fetch_SVM(server_rec* s, apr_pool_t* pool, const char* hSVM, int make) {
  SVM_Obj_holder* SVM_Obj;
  mod_SVMLoc_svr_cfg* svr
    = ap_get_module_config(s->module_config, &svmloc_module);

  SVM_Obj = svr->SVMList;

  while(SVM_Obj->nextSVM != NULL) {
    if(!apr_strnatcasecmp(SVM_Obj->SVM_handler, hSVM))
      break;

    SVM_Obj = (SVM_Obj_holder*)SVM_Obj->nextSVM;
  }

  if(SVM_Obj->nextSVM == NULL) {
    if(make) {
      SVM_Obj->nextSVM = apr_pcalloc(pool, sizeof(SVM_Obj_holder));
      SVM_Obj->SVM_handler = apr_pstrdup(pool, hSVM);
      ((SVM_Obj_holder*)SVM_Obj->nextSVM)->nextSVM = NULL;
      ((SVM_Obj_holder*)SVM_Obj->nextSVM)->pSVM = NULL;
      ((SVM_Obj_holder*)SVM_Obj->nextSVM)->model_filename = NULL;
      ((SVM_Obj_holder*)SVM_Obj->nextSVM)->freqpattern_filename = NULL;
    } else {
      return NULL;
    }
  }

  return SVM_Obj;

}

static const char* modSVMLoc_set_handler(cmd_parms* cmd, void* cfg, const char* HandlerName) {
  SVM_Obj_holder* SVM_Obj;

  SVM_Obj = mod_SVMLoc_fetch_SVM(cmd->server, cmd->pool, HandlerName, 1);

  return NULL;
}

static const char* modSVMLoc_set_model_filename(cmd_parms* cmd, void* cfg, const char* HandlerName, const char* modelFilename) {
  SVM_Obj_holder* SVM_Obj;

  SVM_Obj = mod_SVMLoc_fetch_SVM(cmd->server, cmd->pool, HandlerName, 0);

  if(SVM_Obj == NULL) {
    return "Error, SVM does not exist";
  }

  SVM_Obj->model_filename = apr_pstrdup(cmd->pool, modelFilename);

  if(SVM_Obj->model_filename == NULL) {
    ap_log_error(APLOG_MARK, APLOG_EMERG, 0, cmd->server,
		 "Error, unable to allocate string for modelFilename!");
  }

  return NULL;
}

static const char* modSVMLoc_set_freqpattern_filename(cmd_parms* cmd, void* cfg, const char* HandlerName, const char* freqpatternFilename) {
  SVM_Obj_holder* SVM_Obj;

  SVM_Obj = mod_SVMLoc_fetch_SVM(cmd->server, cmd->pool, HandlerName, 0);

  if(SVM_Obj == NULL) {
    return "Error, SVM does not exist";
  }

  SVM_Obj->freqpattern_filename = apr_pstrdup(cmd->pool, freqpatternFilename);

  if(SVM_Obj->freqpattern_filename == NULL) {
    ap_log_error(APLOG_MARK, APLOG_EMERG, 0, cmd->server,
		 "Error, unable to allocate string for frequent pattern filename!");
  }

  return NULL;
}


static apr_hash_t *parse_form_from_string(request_rec *r, char *args) {
  apr_hash_t *form;
  /*  apr_array_header_t *values = NULL;*/
  char *pair;
  char *eq;
  const char *delim = "&";
  char *last;
  char *values;

  if(args == NULL) {
    return NULL;
  }

  form = apr_hash_make(r->pool);
  
  /* Split the input on '&' */
  for (pair = apr_strtok(args, delim, &last); pair != NULL;
       pair = apr_strtok(NULL, delim, &last)) {
    for (eq = pair; *eq; ++eq) {
      if (*eq == '+') {
	*eq = ' ';
      }
    }

    /* split into key value and unescape it */
    eq = strchr(pair, '=');
    
    if(eq) {
      *eq++ = '\0';
      ap_unescape_url(pair);
      ap_unescape_url(eq);
    } else {
      eq = "";
      ap_unescape_url(pair);
    }

    /* Store key/value pair in out form hash. Given that there
     * may be many values for the same key, we store values
     * in an array (which we'll have to create the first
     * time we encounter the key in question).
     */
    values = apr_hash_get(form, pair, APR_HASH_KEY_STRING);
    if(values != NULL) {
      values = apr_pstrcat(r->pool, values, "&", eq, NULL);
      /*      values = apr_array_make(r->pool, 1, sizeof(const char*));
	      apr_hash_set(form, pair, APR_HASH_KEY_STRING, values);*/
    } else {
      values = apr_pstrdup(r->pool, eq);
    }
    apr_hash_set(form, pair, APR_HASH_KEY_STRING, values);
  }

  return form;
  
}

static apr_hash_t* parse_form_from_GET(request_rec *r) {
  return parse_form_from_string(r, r->args);
}

static int parse_form_from_POST(request_rec* r, apr_hash_t** form) {
  int bytes, eos;
  apr_size_t count;
  apr_status_t rv;
  apr_bucket_brigade *bb;
  apr_bucket_brigade *bbin;
  char *buf;
  apr_bucket *b;
  apr_bucket *nextb;
  const char *clen = apr_table_get(r->headers_in, "Content-Length");
  if(clen != NULL) {
    bytes = strtol(clen, NULL, 0);
    if(bytes >= MAX_SIZE) {
      ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
		    "Request too big (%d bytes; limit %d)",
		    bytes, MAX_SIZE);
      return HTTP_REQUEST_ENTITY_TOO_LARGE;
    }
  } else {
    bytes = MAX_SIZE;
  }

  bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
  bbin = apr_brigade_create(r->pool, r->connection->bucket_alloc);
  count = 0;

  do {
    rv = ap_get_brigade(r->input_filters, bbin, AP_MODE_READBYTES,
			APR_BLOCK_READ, bytes);
    if(rv != APR_SUCCESS) {
      ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
		    "failed to read from input");
      return HTTP_INTERNAL_SERVER_ERROR;
    }
    for (b = APR_BRIGADE_FIRST(bbin);
	 b != APR_BRIGADE_SENTINEL(bbin);
	 b = nextb ) {
      nextb = APR_BUCKET_NEXT(b);
      if(APR_BUCKET_IS_EOS(b) ) {
	eos = 1;
      }
      if (!APR_BUCKET_IS_METADATA(b)) {
	if(b->length != (apr_size_t)(-1)) {
	  count += b->length;
	  if(count > MAX_SIZE) {
	    /* This is more data than we accept, so we're
	     * going to kill the request. But we have to
	     * mop it up first.
	     */
	    apr_bucket_delete(b);
	  }
	}
      }
      if(count <= MAX_SIZE) {
	APR_BUCKET_REMOVE(b);
	APR_BRIGADE_INSERT_TAIL(bb, b);
      }
    }
  } while(!eos);

  /* OK, done with the data. Kill the request if we got too much data. */
  if(count > MAX_SIZE) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
		  "Request too big (%d bytes; limit %d)",
		  bytes, MAX_SIZE);
    return HTTP_REQUEST_ENTITY_TOO_LARGE;
  }

  /* We've got all the data. Now put it in a buffer and parse it. */
  buf = apr_palloc(r->pool, count+1);
  rv = apr_brigade_flatten(bb, buf, &count);
  if(rv != APR_SUCCESS) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
		  "Error (flatten) reading from data");
    return HTTP_INTERNAL_SERVER_ERROR;
  }
  buf[count] = '\0';
  *form = parse_form_from_string(r, buf);
  
  return OK;

}
