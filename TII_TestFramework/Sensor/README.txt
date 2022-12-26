
>  docker build -t test_sensor_image .

# To build the IMAGE for ARM64 platform:
>  docker buildx build --platform linux/arm64 -t test_sensor_image_arm64 . --load

# To save image to the archive:
>  docker save arm64_image  > /home/andtokm/Temp/Docker/sensor.tar

# To restore/load from the archive on the targer machine:
>  scp /home/andtokm/Temp/Docker/sensor.tar root@192.168.1.5:/root/sensor.tar
