# Use an official Ubuntu image as a base
FROM ubuntu:latest

# Set environment variables for non-interactive installation
ENV DEBIAN_FRONTEND=noninteractive

# Update apt and install necessary packages
# build-essential for compiling C++ applications
# libwxgtk3.2-dev for wxWidgets development files
RUN apt-get update && \
    apt-get install -y \
    build-essential \
    libwxgtk3.2-dev \
    python3-wxgtk4.0 \
    wget \
    pipx  && \
    rm -rf /var/lib/apt/lists/*

# Set the working directory inside the container
WORKDIR /app

# Copy the wxWidgets example application
# COPY hello.cpp .

# Compile the wxWidgets application
# `wx-config --cxxflags` provides the necessary compiler flags
# `wx-config --libs` provides the necessary linker flags
# RUN g++ hello.cpp -o hello $(wx-config --cxxflags --libs)
RUN  wget https://archive.chirpmyradio.com/chirp_next/next-20251010/chirp-20251010-py3-none-any.whl && \
     pipx install --system-site-packages ./chirp-20251010-py3-none-any.whl && \
     rm -rf *.whl

# Command to run the application when the container starts
# CMD ["./hello"]
CMD ["/root/.local/bin/chirp"]
