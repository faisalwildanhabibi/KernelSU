#!/system/bin/sh
MODDIR=${0%/*}

# Ensure hide_list exists with default managers
HIDE_LIST="/data/adb/ksu/.hide_list"

if [ ! -f "$HIDE_LIST" ]; then
    touch "$HIDE_LIST"
    echo "me.weishu.kernelsu" >> "$HIDE_LIST"
    echo "org.bakasu.bakasu" >> "$HIDE_LIST"
    echo "io.github.a13e300.ksu" >> "$HIDE_LIST"
    chmod 0644 "$HIDE_LIST"
fi
