#!/bin/python3
# -*- coding: utf-8 -*-

# Copyright © Cloud Linux GmbH & Cloud Linux Software, Inc 2010-2020 All Rights Reserved
#
# Licensed under GNU GPLv2
# https://choosealicense.com/licenses/gpl-2.0/
#
# Authors: Rostyslav Tulchii <rtulchii@cloudlinux.com>

import kernel_panic_receiver

local_server_ip = 'YOUR-LOCAL-SERVER-IP'
local_server_port = 514 
sentry_dsn = 'YOUR-SENTRY-DSN'

def parse_kernel_version(addr, klogs):
    start_idx = klogs.find('.el')
    end_idx = start_idx

    if start_idx == -1: 
        return ['kernel_version', "unknown"]

    while klogs[start_idx - 1] != ' ' or klogs[end_idx] != ' ':
        if (klogs[start_idx - 1] != ' '): 
            start_idx -= 1
        if (klogs[end_idx] != ' '): 
            end_idx += 1

    return ['kernel_version', klogs[start_idx:end_idx]]

kreceiver = kernel_panic_receiver.KernelPanicReceiver(local_server_ip, local_server_port, sentry_dsn)

kreceiver.register_parser_tag(parse_kernel_version)

kreceiver.start_receiving_logs()

