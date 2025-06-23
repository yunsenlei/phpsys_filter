#!/bin/bash
dtrace -G -s probe_provider.d -o probe_provider.o
dtrace -h -s probe_provider.d -o probe_provider.h
./opt/php-7.4/bin/phpize
./configure --with-php-config=/opt/php-7.4/bin/php-config
make