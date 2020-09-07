#!/bin/bash
# -*- coding: utf-8 -*-

# Copyright © Cloud Linux GmbH & Cloud Linux Software, Inc 2010-2020 All Rights Reserved
#
# Licensed under GNU GPLv2
# https://choosealicense.com/licenses/gpl-2.0/
#
# Authors: Rostyslav Tulchii <rtulchii@cloudlinux.com>

NAME=kernel_panic_receiver.py
INSTALLPATH=$(python3 -m site --user-site)

if [ "$(whoami)" != "root" ]
then
	echo "Warning: you should run this script as root"
fi

pip3 install raven

if [ "$?" != "0" ]
then
	echo "Installation has failed: cannot install raven module"
	exit 1
fi

mkdir -p "$INSTALLPATH"

cp "$NAME" "$INSTALLPATH/"

if [ "$?" == "0" ]
then
	echo "Successfully installed (path: $INSTALLPATH/$NAME)"
else
	echo "Installation has failed"
	exit 1
fi

exit 0
