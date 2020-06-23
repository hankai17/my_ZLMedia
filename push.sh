for((;;)); do \
        ffmpeg -re -i ./ori.flv \
        -vcodec copy -acodec copy \
        -f flv rtmp://192.168.0.114:1935/myapp/0; \
        sleep 1; \
done
