
>  docker build -t test_sensor_image .

# To build the IMAGE for ARM64 platform:
>  docker buildx build --platform linux/arm64 -t test_sensor_image_arm64 . --load

# Run container:
>  sudo docker run --net=host -it --name sensor test_sensor_image_arm64

# To save image to the archive:
>  docker save test_sensor_image_arm64  > /home/andtokm/Temp/Docker/sensor.tar

# Upload the image archive to the target device:
>  scp /home/andtokm/Temp/Docker/sensor.tar root@192.168.1.5:/root/sensor.tar
>  scp /home/andtokm/Temp/Docker/sensor.tar root@10.10.10.2:/root/sensor.tar   # Over the ETHERNET


# To restore/load from the archive on the targer machine:
>  docker load < /root/sensor.tar