cmake_minimum_required(VERSION 3.6)
project(nginx)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_FLAGS "-pipe  -O -W -Wall -Wpointer-arith -Wno-unused-parameter -Werror -g ")

set(ALL_INCS
        src/core
        src/event
#        src/event/modules
        src/os/unix
        objs
        src/http
        src/http/modules
        src/http/modules/perl
        src/http/modules/v2
        src/mail
        )

include_directories(${ALL_INCS})

aux_source_directory(. SOURCE_FILES)
aux_source_directory(./src/core SOURCE_FILES)
aux_source_directory(./src/event SOURCE_FILES)
#aux_source_directory(./src/event/modules SOURCE_FILES) # 平台相关不能加入所有的源码
aux_source_directory(./src/os/unix SOURCE_FILES)
aux_source_directory(./src/http SOURCE_FILES)
aux_source_directory(./src/http/modules SOURCE_FILES)

# modify src list
set(SOURCE_FILES ${SOURCE_FILES} ./src/event/modules/ngx_epoll_module.c)
set(SOURCE_FILES ${SOURCE_FILES} ./objs/ngx_modules.c)

# 此次configure不关心的 源码需要剔除掉
list(REMOVE_ITEM SOURCE_FILES ./src/os/unix/ngx_darwin_init.c ./src/os/unix/ngx_darwin_sendfile_chain.c)
list(REMOVE_ITEM SOURCE_FILES ./src/os/unix/ngx_freebsd_init.c ./src/os/unix/ngx_freebsd_sendfile_chain.c)
list(REMOVE_ITEM SOURCE_FILES ./src/os/unix/ngx_solaris_init.c ./src/os/unix/ngx_solaris_sendfilev_chain.c)
list(REMOVE_ITEM SOURCE_FILES ./src/core/ngx_thread_pool.c)
list(REMOVE_ITEM SOURCE_FILES ./src/os/unix/ngx_file_aio_read.c)
list(REMOVE_ITEM SOURCE_FILES ./src/os/unix/ngx_linux_aio_read.c)
list(REMOVE_ITEM SOURCE_FILES ./src/os/unix/ngx_thread_cond.c)
list(REMOVE_ITEM SOURCE_FILES ./src/os/unix/ngx_thread_mutex.c)
list(REMOVE_ITEM SOURCE_FILES ./src/os/unix/ngx_thread_id.c)
list(REMOVE_ITEM SOURCE_FILES ./src/http/modules/ngx_http_dav_module.c)
list(REMOVE_ITEM SOURCE_FILES ./src/http/modules/ngx_http_geoip_module.c)
list(REMOVE_ITEM SOURCE_FILES ./src/http/modules/ngx_http_degradation_module.c)
list(REMOVE_ITEM SOURCE_FILES ./src/http/modules/ngx_http_grpc_module.c)
list(REMOVE_ITEM SOURCE_FILES ./src/http/modules/ngx_http_image_filter_module.c)
list(REMOVE_ITEM SOURCE_FILES ./src/http/modules/ngx_http_stub_status_module.c)

add_executable(nginx ${SOURCE_FILES})
#target_link_libraries(nginx -ldl -lpthread -lpthread -lcrypt -lpcre2-8 -lssl -lcrypto -ldl -lpthread -lz -lGeoIP -lprofiler)
# 引入lib包
TARGET_LINK_LIBRARIES (nginx dl pthread crypt ldap lber pcre ssl crypto dl pthread z xml2 xslt exslt)