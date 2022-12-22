docker buildx build --platform linux/arm64 -t arm64_image . --load
docker save arm64_image  > /home/andtokm/tmp/Docker/sensor.tar
scp /home/andtokm/tmp/Docker/sensor.tar root@192.168.1.5:/root/sensor.tar
