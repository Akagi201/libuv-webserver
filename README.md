libuv-webserver
===============

A lightweight webserver based on libuv and http-parser

## Programming Live Video
* [Ryan Dahl's tutorial](http://vimeo.com/24713213)

## Good http serve on libuv
* <https://github.com/kellabyte/Haywire>
* <https://github.com/h2o/h2o>

## Build & Run
* `./start_build.sh`
* `cd build`
* `make`
* `./libuv_webserver`
* `curl http://127.0.0.1:8000/`

## Stress test
* `ab -n 5000 -c 500 http://127.0.0.1:8000/`

## TODO
* split code into tcp and http part
* http part will transform between structs and http-parser output
* check memory leaks on libuv part.
* build a http response part for easy responses.
* 