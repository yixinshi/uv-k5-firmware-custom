# Change the ui/menu.c/h to support new language

## Build the container images
```
sudo docker build -t uvk5 .
```
The major change is to mount the source code into the container, rather than copy it.


## Compile the firmware.
```
docker run --rm -v ${PWD}/compiled-firmware:/app/compiled-firmware -v ${PWD}:/app uvk5 /bin/bash -c "cd /app && make && cp firmware* compiled-firmware/"
```
