#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <stdbool.h>
#include <unistd.h> // _SC_NPROCESSORS_ONLN on OS X
#include "uv.h"
#include "http-parser/http_parser.h"
#include "lwlog/lwlog.h"

#define MAX_WRITE_HANDLES (1000)
#define HTTP_BODY "helloworld!"

#if 0
#define UV_ERR(err, msg) lwlog_err("%s: %s", msg, uv_err_name(err))

#define UV_CHECK(err, msg) \
do {\
    if (err != 0) {\
        UV_ERR(err, msg); \
        exit(1); \
    }\
} while(0)
#endif

#define UV_ERR(err, msg) lwlog_err("%s: [%s(%d): %s]\n", msg, uv_err_name((err)), (int)err, uv_strerror((err)))

#define UV_CHECK(err, msg) \
do { \
  if (err != 0) { \
    UV_ERR(err, msg); \
    exit(1); \
  } \
} while(0)

static int request_num = 1;
static uv_loop_t *uv_loop;
static uv_tcp_t server;
static http_parser_settings parser_settings;

typedef struct {
    uv_tcp_t handle;
    http_parser parser;
    uv_write_t write_req;
    int request_num;
} client_t;

void on_close(uv_handle_t *handle) {
    client_t *client = (client_t *) handle->data;

    lwlog_info("[ %5d ] connection closed", client->request_num);

    free(client);

    return;
}

void alloc_cb(uv_handle_t * handle/*handle*/, size_t suggested_size, uv_buf_t *buf) {
    *buf = uv_buf_init((char *) malloc(suggested_size), suggested_size);

    return;
}

void on_read(uv_stream_t *tcp, ssize_t nread, const uv_buf_t *buf) {
    ssize_t parsed = 0;
    lwlog_info("on read: %ld", nread);
    client_t *client = (client_t *) tcp->data;
    if (nread >= 0) {
        parsed = (ssize_t) http_parser_execute(
                &client->parser, &parser_settings, buf->base, nread);
        if (parsed < nread) {
            lwlog_err("parse error");
            uv_close((uv_handle_t *) &client->handle, on_close);
        }
    } else {
        if (nread != UV_EOF) {
            UV_ERR(nread, "read");
        }
        uv_close((uv_handle_t *) &client->handle, on_close);
    }
    free(buf->base);

    return;
}

typedef struct {
    uv_work_t request;
    client_t *client;
    bool error;
    char *result;
} render_baton_t;

void after_write(uv_write_t *req, int status) {
    UV_CHECK(status, "write");
    if (!uv_is_closing((uv_handle_t *) req->handle)) {
        // free render_baton_t
        render_baton_t *closure = (render_baton_t *)(req->data);
        free(closure);
        uv_close((uv_handle_t *) req->handle, on_close);
    }

    return;
}

void render(uv_work_t *req) {
    render_baton_t *closure = (render_baton_t *)(req->data);
    client_t *client = (client_t *) closure->client;

    lwlog_info("[ %5d ] render", client->request_num);
    //closure->result = "hello world";
    closure->result = malloc(sizeof(HTTP_BODY));
    snprintf(closure->result, sizeof(HTTP_BODY), HTTP_BODY);

    return;
}

void after_render(uv_work_t *req) {
    render_baton_t *closure = (render_baton_t *)(req->data);
    client_t *client = (client_t *) closure->client;
    char rep[256] = {0};

    lwlog_info("[ %5d ] after render", client->request_num);

    snprintf(rep, sizeof(rep), "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: keep-alive\r\nContent-Length: %d\r\n\r\n%s", strlen(closure->result), closure->result);


    uv_buf_t resbuf;
    resbuf.base = (char *) rep;
    resbuf.len = strlen(rep);

    client->write_req.data = closure;

    // https://github.com/joyent/libuv/issues/344
    int r = uv_write(&client->write_req,
            (uv_stream_t *) &client->handle,
            &resbuf,
            1,
            after_write);
    UV_CHECK(r, "write buff");

    return;
}

int on_message_begin(http_parser * parser/*parser*/) {
    lwlog_info("\n***MESSAGE BEGIN***\n");

    return 0;
}

int on_headers_complete(http_parser * parser/*parser*/) {
    lwlog_info("\n***HEADERS COMPLETE***\n");

    return 0;
}

int on_url(http_parser * parser/*parser*/, const char *at, size_t length) {
    lwlog_info("Url: %.*s", (int) length, at);

    return 0;
}

int on_header_field(http_parser * parser/*parser*/, const char *at, size_t length) {
    lwlog_info("Header field: %.*s", (int) length, at);

    return 0;
}

int on_header_value(http_parser * parser/*parser*/, const char *at, size_t length) {
    lwlog_info("Header value: %.*s", (int) length, at);

    return 0;
}

int on_body(http_parser * parser/*parser*/, const char *at, size_t length) {
    lwlog_info("Body: %.*s", (int) length, at);

    return 0;
}

int on_message_complete(http_parser *parser) {
    lwlog_info("\n***MESSAGE COMPLETE***\n");

    client_t *client = (client_t *) parser->data;

    lwlog_info("[ %5d ] on_message_complete", client->request_num);
    render_baton_t *closure = malloc(sizeof(render_baton_t));
    closure->request.data = closure;
    closure->client = client;
    closure->error = false;
    int status = uv_queue_work(uv_default_loop(),
            &closure->request,
            render,
            (uv_after_work_cb) after_render);
    UV_CHECK(status, "uv_queue_work");
    assert(status == 0);

    return 0;
}

void on_connect(uv_stream_t *server_handle, int status) {
    int ret = 0;
    client_t *client = NULL;
    UV_CHECK(status, "connect");
    assert((uv_tcp_t *) server_handle == &server);

    client = (client_t *) malloc(sizeof(client_t));
    client->request_num = request_num;
    ++request_num;

    lwlog_info("[ %5d ] new connection", request_num);

    uv_tcp_init(uv_loop, &client->handle);
    http_parser_init(&client->parser, HTTP_REQUEST);

    client->parser.data = client;
    client->handle.data = client;

    ret = uv_accept(server_handle, (uv_stream_t *) &client->handle);
    UV_CHECK(ret, "accept");

    uv_read_start((uv_stream_t *) &client->handle, alloc_cb, on_read);

    return;
}

int main(int argc, char *argv[]) {
    long cores = 0;
    char cores_string[10] = {0};
    int ret = 0;
    struct sockaddr_in address;

    signal(SIGPIPE, SIG_IGN);

    cores = sysconf(_SC_NPROCESSORS_ONLN);
    lwlog_info("Number of available CPU cores %ld", cores);
    snprintf(cores_string, sizeof(cores_string), "%d", cores);
    setenv("UV_THREADPOOL_SIZE", cores_string, 1);

    parser_settings.on_message_begin = on_message_begin;
    parser_settings.on_url = on_url;
    parser_settings.on_header_field = on_header_field;
    parser_settings.on_header_value = on_header_value;
    parser_settings.on_headers_complete = on_headers_complete;
    parser_settings.on_body = on_body;
    parser_settings.on_message_complete = on_message_complete;

    uv_loop = uv_default_loop();

    ret = uv_tcp_init(uv_loop, &server);
    UV_CHECK(ret, "tcp_init");

    ret = uv_tcp_keepalive(&server, 1, 60);
    UV_CHECK(ret, "tcp_keepalive");

    ret = uv_ip4_addr("0.0.0.0", 8000, &address);
    UV_CHECK(ret, "ip4_addr");

    ret = uv_tcp_bind(&server, (const struct sockaddr *) &address, 0);
    UV_CHECK(ret, "tcp_bind");

    ret = uv_listen((uv_stream_t *) &server, MAX_WRITE_HANDLES, on_connect);
    UV_CHECK(ret, "uv_listen");

    lwlog_info("listening on port 8000");

    uv_run(uv_loop, UV_RUN_DEFAULT);

    return 0;
}
