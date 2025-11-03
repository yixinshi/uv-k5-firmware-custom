# Change the ui/menu.c/h to support new language

## Build the container images
```
sudo docker build -t uvk5 .
```

## Compile the firmware.
The major change is to mount the source code into the container, rather than copying it into the docker image.
```
docker run --rm -v ${PWD}/compiled-firmware:/app/compiled-firmware -v ${PWD}:/app uvk5 /bin/bash -c "cd /app && make && cp firmware* compiled-firmware/"
```

## Flash the firmware into the radio.
Make sure the radio is turned on in programming mode (PTT + Power).
```
pip install pyserial
python quansheng_flasher.py --port /dev/ttyUSB0 ../compiled-firmware/egzumer_v0.22.packed.bin
```
