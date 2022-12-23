docker buildx build --platform linux/arm64 -t test_sensor_image_arm64 . --load
docker save arm64_image  > /home/andtokm/Temp/Docker/sensor.tar
scp /home/andtokm/Temp/Docker/sensor.tar root@192.168.1.5:/root/sensor.tar
