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

kreceiver = kernel_panic_receiver.KernelPanicReceiver(local_server_ip, local_server_port, sentry_dsn)

kreceiver.start_receiving_logs()

