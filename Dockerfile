# Use Ubuntu 20.04 as base image
FROM ubuntu:20.04

ARG DEBIAN_FRONTEND=noninteractive
ENV TZ=Etc/UTC

# # Install dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    libssl-dev \
    wget \
    libgmp-dev \
    libtool \
    autoconf \
    automake \
    pkg-config \
    libjsoncpp-dev \
    libsecp256k1-dev
# Install nlohmann/json
RUN apt-get install -y nlohmann-json3-dev

# Install Crypto++ library
# RUN apt-get install -y libcryptopp-dev # chat gpt suggest
RUN apt-get install -y libcrypto++-dev # actual package


# Install secp256k1
RUN git clone https://github.com/bitcoin-core/secp256k1.git && \
    cd secp256k1 && \
    ./autogen.sh && \
    ./configure --enable-module-recovery && \
    make && make install

# Set working directory
WORKDIR /app

# Copy current directory to /app
COPY . /app

# Build the application
# RUN cmake . && make

# Set entrypoint
# ENTRYPOINT ["./eip712_signer"]
