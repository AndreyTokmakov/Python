

# docker build -t csl_tests_img -f docker/Dockerfile .

# ARM64
docker buildx build --platform linux/arm64 -f docker/Dockerfile -t csl_tests_img_arm64 . --load


# To save image to the archive:
docker save csl_tests_img_arm64  > /home/andtokm/DiskS/Temp/Docker/csl_tests_img_arm64.tar

# To restore/load from the archive on the targer machine:
docker load < /root/csl_tests_img_arm64.tar

# Prune images
docker image prune -a

docker run --rm -it --net=host --name csl_sensor_container csl_tests_img_arm64 /bin/bash






# Upload the image archive to the target device:
scp /home/andtokm/DiskS/Temp/Docker/csl_tests_img_arm64.tar root@192.168.1.5:/root/csl_tests_img_arm64.tar
scp /home/andtokm/DiskS/Temp/Docker/csl_tests_img_arm64.tar root@192.168.1.6:/root/csl_tests_img_arm64.tar


# Over the ETHERNET
scp /home/andtokm/DiskS/Temp/Docker/csl_tests_img_arm64.tar root@10.10.10.2:/root/csl_tests_img_arm64.tar

