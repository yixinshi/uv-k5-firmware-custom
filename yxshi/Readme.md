Command to run:

# Allow any client to connect to the DISPLAY
$xhost +
# Run the GUI app.
sudo docker run -it --rm -e DISPLAY=$DISPLAY -v /tmp/.X11-unix:/tmp/.X11-unix wx-hello

# How to make the app access the serial port.
# Find the tty port name
$sudo dmesg|grep tty
[    0.085845] printk: legacy console [tty0] enabled
[    2.866006] usb 1-2: pl2303 converter now attached to ttyUSB0

# Find out the groups.
(venv) ant@sam:~/github/uv-k5-firmware-custom/yxshi$ echo $USER
(venv) ant@sam:~/github/uv-k5-firmware-custom/yxshi$ groups ant
ant : ant adm cdrom sudo dip plugdev users lpadmin docker

# Add yourself intot dialout group
(venv) ant@sam:~/github/uv-k5-firmware-custom/yxshi$ sudo usermod -a -G dialout $USER
(venv) ant@sam:~/github/uv-k5-firmware-custom/yxshi$ groups

# Logout
(venv) ant@sam:~/github/uv-k5-firmware-custom/yxshi$ sudo docker run -it --rm --device=/dev/ttyUSB0:/dev/ttyUSB0 -e DISPLAY=$DISPLAY -v /tmp/.X11-unix:/tmp/.X11-unix wx-hello
