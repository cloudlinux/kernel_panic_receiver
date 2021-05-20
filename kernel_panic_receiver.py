#!/bin/python3
# -*- coding: utf-8 -*-

# Copyright © Cloud Linux GmbH & Cloud Linux Software, Inc 2010-2020 All Rights Reserved
#
# Licensed under GNU GPLv2
# https://choosealicense.com/licenses/gpl-2.0/
#
# Authors: Rostyslav Tulchii <rtulchii@cloudlinux.com>

import socket
import time
from threading import Thread
from threading import Lock
from datetime import datetime

from raven import Client

def find_and_slice(string, substring, delim='\n'):
    start_idx = string.find(substring)
    if start_idx == -1:
        return None
    end_idx = string.find(delim, start_idx)
    return string[start_idx:end_idx]

class KernelPanicReceiver(object):

    @staticmethod
    def default_parser_title__(addr, klogs):
        key_words = [ "BUG", "Kernel panic", "kernel stack overflow", "divide error", "general protection fault", "SMP" ]
        for key in key_words:
            title = find_and_slice(klogs, key)
            if title is not None:
                break
        if title is None:
            title = "Unknown error"
        title = " ".join(title.split())
        idx = klogs.find("[kmodlve]")
        if idx != -1:
            title = "[kmodlve] " + title
        return title

    @staticmethod
    def default_parser_user__(addr, klogs):
        return addr[0]

    @staticmethod
    def default_parser_fingerprint__(addr, klogs):
        return KernelPanicReceiver.default_parser_title__(addr, klogs)

    @staticmethod
    def default_parser_message__(addr, klogs):
        return "\n\nKERNEL LOGS:\n\n" + klogs

    def __init__(self, listen_host, listen_port, sentry_dsn):
        """
            listen_host, listen_port - ip/port that will be listened to
            sentry_dsn - sentry DSN
        """
        # sentry init
        self._sentry_client = Client(sentry_dsn)

        # server init
        self._host = listen_host
        self._port = listen_port
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._server_socket.bind((self._host, self._port))

        # data structure init
        self.received_all = {}
        self.received_all_mtx = Lock()
        self.data_available = False
        self.list_recv = []
        self.server_mutex = Lock()

        self._parser_title = KernelPanicReceiver.default_parser_title__
        self._parser_user = KernelPanicReceiver.default_parser_user__
        self._parser_fingerprint = KernelPanicReceiver.default_parser_fingerprint__
        self._parser_message = KernelPanicReceiver.default_parser_message__

        self._parsers_tags = []
        self._parsers_extra = []

    def send_to_sentry_(self, title, fingerprint, message, user_id, tags, extra):

        event = {
                    'message': title + message,
                    'fingerprint': [fingerprint],
                    'level': 'fatal',
                    'user': {'id': user_id},
                    'tags': tags,
                    'extra': extra,
                    'platform': 'python'
                }

        return self._sentry_client.send(**event)

    def _process_panic_msg(self, key):
        """
            Process logs when they are all received
            key - list with ip / port
        """
        with self.received_all_mtx:
            klogs = self.received_all[key].decode("ascii")
            self.received_all.pop(key)

        title = self._parser_title(key, klogs)
        user = self._parser_user(key, klogs)
        fingerprint = self._parser_fingerprint(key, klogs)
        message = self._parser_message(key, klogs)

        tags = []
        for f_parser in self._parsers_tags:
            ret = f_parser(key, klogs)
            if ret is not None:
                tags.append(ret)

        extra = {}
        for f_parser in self._parsers_extra:
            ret = f_parser(key, klogs)
            if ret is not None:
                extra[ret[0]] = ret[1]

        self.send_to_sentry_(title, fingerprint, message, user, tags, extra)

        print('[', datetime.now(), '] ', key, ' sending logs to sentry [DONE]', sep='')

    def _wait_for_all_data(self, key):
        """
            Waits for all udp packages from specific host are received
            (if for past 2 seconds there were no new packages we suppose that's all data)
            key - list with ip / port
        """
        with self.received_all_mtx:
            cur_len = len(self.received_all.get(key))

        prev_len = 0

        # wait for all logs are received
        while prev_len != cur_len:
            prev_len = cur_len
            print('[', datetime.now(), '] ', key, " waiting for all data", sep='')
            time.sleep(2)
            self.received_all_mtx.acquire()
            cur_len = len(self.received_all.get(key))
            self.received_all_mtx.release()

        self._process_panic_msg(key)

    def _monitor_data(self):
        """
            Waits for new data in global list_recv list which contains received udp packages
        """
        while True:
            while not self.data_available:
                time.sleep(0.01)

            self.server_mutex.acquire()
            local_list_recv = self.list_recv
            self.list_recv = []
            self.data_available = False
            self.server_mutex.release()

            while local_list_recv:
                d = local_list_recv.pop(0)
                received = d[0]
                client_addr = d[1]

                self.received_all_mtx.acquire()
                # first udp package we get from the specific host
                if self.received_all.get(client_addr) is None:
                    self.received_all[client_addr] = received
                    thread = Thread(target=self._wait_for_all_data, args=(client_addr, ), daemon=True)
                    thread.start()
                # not first
                else:
                    self.received_all[client_addr] += received
                self.received_all_mtx.release()

    def register_parser_title(self, f_parser):
        self._parser_title = f_parser

    def register_parser_user(self, f_parser):
        self._parser_user = f_parser

    def register_parser_fingerprint(self, f_parser):
        self._parser_fingerprint = f_parser

    def register_parser_message(self, f_parser):
        self._parser_message = f_parser

    def register_parser_tag(self, f_parser):
        """
            Register a hook that will be called when all logs from a specific host are received
            A returned value of the hook will be sent to sentry as tag
            args:
                f_parser - a function (hook) that has to be registered.
                           prototype: f_parser(addr, klogs)
                                      addr - list with client's ip / port
                                      klogs - string with all logs

            Return value: none
        """
        self._parsers_tags.append(f_parser)

    def unregister_parser_tag(self, f_parser):
        """
            Unregisters a function registered with register_parser_tag()
            args:
                f_parser - a function that has to be unregistered

            Return value:
                True - successfully unregistered
                False - error occured
        """
        try:
            self._parsers_tags.remove(f_parser)
        except:
            return False
        return True

    def register_parser_extra(self, f_parser):
        """
            Register a hook that will be called when all logs from a specific host are received
            A returned value of the hook will be sent to sentry as extra field
            args:
                f_parser - a function (hook) that has to be registered.
                           prototype: f_parser(addr, klogs)
                                      addr - list with client's ip / port
                                      klogs - string with all logs

            Return value: none
        """
        self._parsers_extra.append(f_parser)

    def unregister_parser_extra(self, f_parser):
        """
            Unregisters a function registered with register_parser_extra()
            args:
                f_parser - a function to unregister

            Return value:
                True - successfully unregistered
                False - error occured
        """
        try:
            self._parsers_extra.remove(f_parser)
        except:
            return False
        return True

    def start_receiving_logs(self):
        """
            Starts receiving logs
            Blocking method
        """
        thread = Thread(target=self._monitor_data, args=(), daemon=True)
        thread.start()
        print('[', datetime.now(), '] ', 'Start listening...', sep='')
        while True:
            d = self._server_socket.recvfrom(8192)
            self.server_mutex.acquire()
            self.list_recv.append(d)
            self.data_available = True
            self.server_mutex.release()
