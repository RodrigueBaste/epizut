FROM ubuntu:22.04

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive

# Install required packages
RUN apt-get update && apt-get install -y \
    build-essential \
    linux-headers-generic \
    git \
    openssh-server \
    sudo \
    netcat \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user
RUN useradd -m -s /bin/bash victim && \
    echo "victim:victim" | chpasswd && \
    echo "victim ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# Set up SSH
RUN mkdir -p /var/run/sshd && \
    echo "PermitRootLogin no" >> /etc/ssh/sshd_config && \
    echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config && \
    echo "X11Forwarding yes" >> /etc/ssh/sshd_config && \
    echo "PrintMotd no" >> /etc/ssh/sshd_config && \
    echo "Port 22" >> /etc/ssh/sshd_config && \
    echo "ListenAddress 0.0.0.0" >> /etc/ssh/sshd_config

# Create working directory
WORKDIR /home/victim/epirootkit

# Copy the rootkit source code
COPY rootkit /home/victim/epirootkit/rootkit/

# Set permissions
RUN chown -R victim:victim /home/victim/epirootkit

# Switch to non-root user
USER victim

# Expose SSH port
EXPOSE 22

# Start SSH service
CMD ["sudo", "/usr/sbin/sshd", "-D"] 