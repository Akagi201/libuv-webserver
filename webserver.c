#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h> // _SC_NPROCESSORS_ONLN on OS X
#include "uv.h"
#include "http-parser/http_parser.h"
#include "lwlog/lwlog.h"

#define HTTP_PORT (8000)
#define MAX_WRITE_HANDLES (1000)
#define INDEX_HTML "index.html"

#define GETCONF \
    "HTTP/1.1 200 OK\r\n" \
    "Content-Type: text/plain\r\n" \
    "\r\n"\
    "rtmp://pili-in.qiniu.com/livestream/9dom822q|b68074ef-2852-45d7-b709-93345bc4ca2a\r\n"

#define RESPONSE_HEADER \
    "HTTP/1.1 200 OK\r\n" \
    "Content-Type: text/plain\r\n" \
    "\r\n"

static char http_header[] = "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html\r\n"
        "\r\n"
        "%s";

#define HTTP_HEADER "HTTP/1.1 200 OK\r\n" \
    "Content-Type: text/html\r\n" \
    "\r\n"

#define MAX_HTTP_HEADERS (20)

#define UV_ERR(err, msg) lwlog_err("%s: [%s(%d): %s]\n", msg, uv_err_name((err)), (int)err, uv_strerror((err)))

#define UV_CHECK(err, msg) \
do { \
  if (err != 0) { \
    UV_ERR(err, msg); \
    exit(1); \
  } \
} while(0)

/**
* Represents a single http header.
*/
typedef struct {
    const char *field;
    const char *value;
    size_t field_length;
    size_t value_length;
} http_header_t;

/**
* Represents a http request with internal dependencies.
*
* - write request for sending the response
* - reference to tcp socket as write stream
* - instance of http_parser parser
* - string of the http url
* - string of the http method
* - amount of total header lines
* - http header array
* - body content
*/
typedef struct {
    uv_write_t req;
    uv_stream_t stream;
    http_parser parser;
    char *url;
    char *method;
    int header_lines;
    http_header_t headers[MAX_HTTP_HEADERS];
    const char *body;
    uv_buf_t resp_buf[2];
} http_request_t;

static int request_num = 0;
static uv_loop_t *uv_loop;
static uv_tcp_t server;
static http_parser_settings parser_settings;
static int parsed_url = 0;

void on_close(uv_handle_t *handle) {

    http_request_t *http_request = (http_request_t *) handle->data;

    lwlog_info("connection closed");

    free(http_request);

    return;
}

void alloc_cb(uv_handle_t *handle/*handle*/, size_t suggested_size, uv_buf_t *buf) {
    *buf = uv_buf_init((char *) malloc(suggested_size), suggested_size);

    return;
}

void on_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
    ssize_t parsed = 0;
    lwlog_info("on read, nread: %ld", nread);

    /* get back our http request*/
    http_request_t *http_request = stream->data;

    if (nread >= 0) {
        /*  call our http parser on the received tcp payload */
        parsed = (ssize_t) http_parser_execute(
                &http_request->parser, &parser_settings, buf->base, nread);
        if (parsed < nread) {
            lwlog_err("parse error");
            uv_close((uv_handle_t *) &http_request->stream, on_close);
        }
    } else {
        if (nread != UV_EOF) {
            UV_ERR(nread, "Read error");
        }
        uv_close((uv_handle_t *) &http_request->stream, on_close);
    }
    free(buf->base);

    return;
}

/**
* Initializes default values, counters.
*/
int on_message_begin(http_parser *parser/*parser*/) {
    lwlog_info("***MESSAGE BEGIN***");
    http_request_t *http_request = parser->data;
    http_request->header_lines = 0;

    return 0;
}

/**
* Extract the method name.
*/
int on_headers_complete(http_parser *parser/*parser*/) {
    lwlog_info("***HEADERS COMPLETE***");

    http_request_t *http_request = parser->data;

    const char *method = http_method_str(parser->method);

    http_request->method = malloc(sizeof(method));
    strncpy(http_request->method, method, strlen(method));

    return 0;
}

/**
* Copies url string to http_request->url.
*/
int on_url(http_parser *parser/*parser*/, const char *at, size_t length) {
    lwlog_info("Url: %.*s", (int) length, at);

    http_request_t *http_request = parser->data;

    http_request->url = malloc(length + 1);

    strncpy((char *) http_request->url, at, length);

    return 0;
}

/**
* Copy the header field name to the current header item.
*/
int on_header_field(http_parser *parser/*parser*/, const char *at, size_t length) {
    lwlog_info("Header field: %.*s", (int) length, at);

    http_request_t *http_request = parser->data;

    http_header_t *header = &http_request->headers[http_request->header_lines];

    header->field = malloc(length + 1);
    header->field_length = length;

    strncpy((char *) header->field, at, length);

    return 0;
}

/**
* Now copy its assigned value.
*/
int on_header_value(http_parser *parser/*parser*/, const char *at, size_t length) {
    lwlog_info("Header value: %.*s", (int) length, at);

    http_request_t *http_request = parser->data;

    http_header_t *header = &http_request->headers[http_request->header_lines];

    header->value = malloc(length + 1);
    header->value_length = length;

    strncpy((char *) header->value, at, length);

    ++http_request->header_lines;

    return 0;
}

int on_body(http_parser *parser/*parser*/, const char *at, size_t length) {
    lwlog_info("Body: %.*s", (int) length, at);
    http_request_t *http_request = parser->data;

    http_request->body = malloc(length + 1);
    http_request->body = at;

    return 0;
}

#if 0
void tcp_write_cb(uv_write_t *req, int status) {
    char *buf = NULL;
    UV_CHECK(status, "tcp_write");
    buf = (char *)req->data;
    if (!uv_is_closing((uv_handle_t*)req->handle)) {
        uv_close((uv_handle_t *) req->handle, on_close);
    }

    return;
}
#endif

/**
* Closes current tcp socket after write.
*/
void on_nobuf_write(uv_write_t *req, int status){
    int i = 0;
    http_header_t *header = NULL;
    http_request_t *http_request = req->data;
    UV_CHECK(status, "on_nobuf_write");

    free(http_request->url);
    free(http_request->method);
    for (i = 0; i < http_request->header_lines; ++i) {
        header = &http_request->headers[i];
        free(header->field);
        free(header->value);
    }

    if (!uv_is_closing((uv_handle_t*)req->handle)) {
        uv_close((uv_handle_t *) req->handle, on_close);
    }

    return;
}

/**
* Closes current tcp socket after write.
*/
void on_buf_write(uv_write_t *req, int status) {
    int i = 0;
    char *buf = NULL;
    http_header_t *header = NULL;
    http_request_t *http_request = req->data;

    UV_CHECK(status, "on_buf_write");
    buf = (char *)http_request->resp_buf[1].base;

    if (NULL != buf) {
        free(buf);
        buf = NULL;
    }

    free(http_request->url);
    free(http_request->method);
    if (http_request->body != NULL) {
        free(http_request->body);
    }
    for (i = 0; i < http_request->header_lines; ++i) {
        header = &http_request->headers[i];
        free(header->field);
        free(header->value);
    }

    if (!uv_is_closing((uv_handle_t*)req->handle)) {
        uv_close((uv_handle_t *) req->handle, on_close);
    }

    return;
}

int on_message_complete(http_parser *parser) {
    int i = 0;
    http_header_t *header = NULL;

    lwlog_info("***MESSAGE COMPLETE***");

    http_request_t *http_request = parser->data;
    #if 0
    /* now print the ordered http http_request to console */
    printf("url: %s\n", http_request->url);
    printf("method: %s\n", http_request->method);
    for (int i = 0; i < 5; i++) {
        http_header_t *header = &http_request->headers[i];
        if (header->field)
            printf("Header: %s: %s\n", header->field, header->value);
    }
    printf("body: %s\n", http_request->body);
    printf("\r\n");
    #endif

    //http_request->req.data = NULL;

    if (0 == strcmp(http_request->url, "/")) {
        lwlog_info("root");
        char *file_contents;
        long input_file_size;

#if 0
        resp_buf.base = malloc(input_file_size + sizeof(http_header) + 1);

        sprintf(resp_buf.base, http_header, file_contents);
        /* set the http response to the buffer */
        //resp_buf.base = file_contents;
        resp_buf.len = input_file_size + sizeof(http_header);


        resp_buf.base = malloc(input_file_size + sizeof(HTTP_HEADER) + 1);
        sprintf(resp_buf.base, "%s", HTTP_HEADER file_contents);
        resp_buf.len = input_file_size + sizeof(HTTP_HEADER) + 1;

        free(file_contents);
        http_request->req.data = resp_buf.base;
#endif

        // send http response header
        http_request->resp_buf[0].base = HTTP_HEADER;
        http_request->resp_buf[0].len = sizeof(HTTP_HEADER);

        // send http response body
        FILE *input_file = fopen(INDEX_HTML, "rb");
        fseek(input_file, 0, SEEK_END);
        input_file_size = ftell(input_file);
        rewind(input_file);
        file_contents = malloc(input_file_size * (sizeof(char)));
        fread(file_contents, sizeof(char), (size_t)input_file_size, input_file);
        fclose(input_file);

        lwlog_info("input_file_size: %ld", input_file_size);

        http_request->resp_buf[1].base = file_contents;
        http_request->resp_buf[1].len = (size_t)input_file_size;

        /* lets send our short http hello world response and close the socket */
        //uv_write(&http_request->req, &http_request->stream, &resp_buf, 1, tcp_write_cb);
        uv_write(&http_request->req, &http_request->stream, http_request->resp_buf, 2, on_buf_write);
    }

    if (0 == strcmp(http_request->url, "/getconf")) {
        lwlog_info("getconf");
        http_request->resp_buf[0].base = GETCONF;
        http_request->resp_buf[0].len = sizeof(GETCONF);
        /* lets send our short http hello world response and close the socket */
        uv_write(&http_request->req, &http_request->stream, http_request->resp_buf, 1, on_nobuf_write);
    }

    if (0 == strcmp(http_request->url, "/setconf")) {
        lwlog_info("setconf");
        http_request->resp_buf[0].base = RESPONSE_HEADER;
        http_request->resp_buf[0].len = sizeof(RESPONSE_HEADER);
        /* lets send our short http hello world response and close the socket */
        uv_write(&http_request->req, &http_request->stream, http_request->resp_buf, 1, on_nobuf_write);
    }

    if (0 == strcmp(http_request->url, "/start")) {
        lwlog_info("start");
        http_request->resp_buf[0].base = RESPONSE_HEADER;
        http_request->resp_buf[0].len = sizeof(RESPONSE_HEADER);
        /* lets send our short http hello world response and close the socket */
        uv_write(&http_request->req, &http_request->stream, http_request->resp_buf, 1, on_nobuf_write);
    }

    if (0 == strcmp(http_request->url, "/stop")) {
        lwlog_info("stop");
        http_request->resp_buf[0].base = RESPONSE_HEADER;
        http_request->resp_buf[0].len = sizeof(RESPONSE_HEADER);
        /* lets send our short http hello world response and close the socket */
        uv_write(&http_request->req, &http_request->stream, http_request->resp_buf, 1, on_nobuf_write);
    }

    // free http parser related malloc
#if 0
    free(http_request->url);
    free(http_request->method);
    free(http_request->body);
    for (i = 0; i < http_request->header_lines; ++i) {
        header = &http_request->headers[i];
        free(header->field);
        free(header->value);
    }
#endif

    return 0;
}

void on_connect(uv_stream_t *server_handle, int status) {
    int ret = 0;
    UV_CHECK(status, "connect");
    assert((uv_tcp_t *) server_handle == &server);

    /* initialize a new http http_request struct */
    http_request_t *http_request = malloc(sizeof(http_request_t));

    /* create an extra tcp handle for the http_request */
    uv_tcp_init(uv_loop, (uv_tcp_t *) &http_request->stream);

    /* set references so we can use our http_request in http_parser and libuv */
    http_request->stream.data = http_request;
    http_request->parser.data = http_request;
    http_request->req.data = http_request;

    /* accept the created http_request */
    ret = uv_accept(server_handle, &http_request->stream);
    if (ret == 0) {
        /* initialize our http parser */
        http_parser_init(&http_request->parser, HTTP_REQUEST);
        /* start reading from the tcp http_request socket */
        uv_read_start(&http_request->stream, alloc_cb, on_read);
    } else {
        /* we seem to have an error and quit */
        uv_close((uv_handle_t *) &http_request->stream, on_close);
        //UV_CHECK(ret, "accept");
    }

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
    snprintf(cores_string, sizeof(cores_string), "%ld", cores);
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

    //ret = uv_tcp_keepalive(&server, 1, 60);
    //UV_CHECK(ret, "tcp_keepalive");

    ret = uv_ip4_addr("0.0.0.0", HTTP_PORT, &address);
    UV_CHECK(ret, "ip4_addr");

    ret = uv_tcp_bind(&server, (const struct sockaddr *) &address, 0);
    UV_CHECK(ret, "tcp_bind");

    ret = uv_listen((uv_stream_t *) &server, MAX_WRITE_HANDLES, on_connect);
    UV_CHECK(ret, "uv_listen");

    lwlog_info("Listening on port %d", HTTP_PORT);

    uv_run(uv_loop, UV_RUN_DEFAULT);

    return 0;
}
