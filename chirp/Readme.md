
# Build Chirp docker image and run it in Ubuntu.

## Build containers.
```
$ docker build -t chirp .
```
## Allow any client to connect to the DISPLAY
```
$ xhost +
```
Without this, you may need to add two more flags:  `-v "$HOME/.Xauthority:/root/.Xauthority:ro" -e XAUTHORITY=/root/.Xauthority`

## Test to run the GUI app
```
$ sudo docker run -it --rm -e DISPLAY=$DISPLAY -v /tmp/.X11-unix:/tmp/.X11-unix chirp
```
You should be able to see the GUI app.

# Make the app access the serial port.

## Find the tty port name
First connect your cable to the serial port and turn on your radio.
```
$ sudo dmesg|grep tty
[    0.085845] printk: legacy console [tty0] enabled
[    2.866006] usb 1-2: pl2303 converter now attached to *ttyUSB0*
```

## Find out the groups
```
(venv) ant@sam:~/github/uv-k5-firmware-custom/yxshi$ echo $USER
(venv) ant@sam:~/github/uv-k5-firmware-custom/yxshi$ groups $USER
ant : ant adm cdrom sudo dip plugdev users lpadmin docker
```

## Add yourself into dialout group
```
(venv) ant@sam:~/github/uv-k5-firmware-custom/yxshi$ sudo usermod -a -G dialout $USER
(venv) ant@sam:~/github/uv-k5-firmware-custom/yxshi$ groups
```

# Logout to make the groups work!!

## Run the docker container
```
(venv) ant@sam:~/github/uv-k5-firmware-custom/yxshi$ sudo docker run -it --rm --device=/dev/ttyUSB0:/dev/ttyUSB0 -e DISPLAY=$DISPLAY -v /tmp/.X11-unix:/tmp/.X11-unix chirp
```
