cd /nginx-1.22.0-ch
./configure  --with-debug --with-cc-opt='-g -O0' --with-stream --add-dynamic-module=/nginx-1.22.0-ch/src/additional/hash_count
make modules
make -j4
#cd objs
#./nginx -c /nginx-1.22.0-ch/conf/nginx.conf