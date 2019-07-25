#!/bin/bash
STATUS=$(curl -s localhost:12345/connector/status | grep status=)
echo $STATUS
if [[ $STATUS != "status=OK" ]]; then
    echo "Run reset routine"
    for i in /sys/bus/pci/drivers/[uoex]hci_hcd/*:*; do
      [[ -e "$i" ]] || continue
      echo "${i##*/}" > "${i%/*}/unbind"
      echo "${i##*/}" > "${i%/*}/bind"
    done
else
    echo "The reset routine did NOT run"
fi
