#include <mongoose.h>

static void event_handler(struct mg_connection *c, int ev, void *ev_data, void *fn_data) 
{
    if (ev == MG_EV_HTTP_MSG) {
        struct mg_http_message *hm = (struct mg_http_message *) ev_data;
        if (mg_http_match_uri(hm, "/websocket")) {
            // Upgrade to websocket
            mg_ws_upgrade(c, hm, NULL);
        } else {
            mg_http_reply(c, 200, "", "Hello TLS!\n");
        }
    } else if (ev == MG_EV_WS_MSG) {
        // Handle websocket messages
        struct mg_ws_message *wm = (struct mg_ws_message *) ev_data;
        mg_ws_send(c, wm->data.ptr, wm->data.len, WEBSOCKET_OP_TEXT);
    }
}

int websocketsrv::start(void) 
{
    mg_mgr_init(&m_mgr);
    
    // Create TLS listener - note the "s" in "wss" and certificate options
    struct mg_connection *c = mg_http_listen(&m_mgr, "wss://0.0.0.0:8443", event_handler, NULL);
    
    if (c == NULL) {
        spdlog::error("Failed to create TLS listener");
        return VSCP_ERROR_GENERIC;
    }
    
    // Set TLS certificate and key
    struct mg_tls_opts opts = {};
    opts.cert = m_cert_path.c_str();  // Path to certificate file
    opts.key = m_key_path.c_str();    // Path to private key file
    opts.ca = m_ca_path.c_str();      // Path to CA file (optional)
    
    // Apply TLS settings
    mg_tls_init(c, &opts);
    
    spdlog::info("TLS WebSocket server started on wss://0.0.0.0:8443");
    
    // Event loop
    while (!m_bQuit) {
        mg_mgr_poll(&m_mgr, 1000);
    }
    
    mg_mgr_free(&m_mgr);
    return VSCP_ERROR_SUCCESS;
}