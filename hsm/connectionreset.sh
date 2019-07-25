#!/bin/bash
STATUS=$(curl -s localhost:12345/connector/status | grep status=)
if [ $STATUS != "status=OK" ]; then
    for i in /sys/bus/pci/drivers/[uoex]hci_hcd/*:*; do
      [ -e "$i" ] || continue
      echo "${i##*/}" > "${i%/*}/unbind"
      echo "${i##*/}" > "${i%/*}/bind"
    done
fi
