FROM ubuntu:22.04

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive

# Install required packages
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    git \
    build-essential \
    netcat \
    openssh-server \
    sudo \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip3 install flask flask-cors cryptography

# Create a non-root user
RUN useradd -m -s /bin/bash attacker && \
    echo "attacker:attacker" | chpasswd && \
    echo "attacker ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# Set up SSH
RUN mkdir -p /var/run/sshd && \
    echo "PermitRootLogin no" >> /etc/ssh/sshd_config && \
    echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config && \
    echo "X11Forwarding yes" >> /etc/ssh/sshd_config && \
    echo "PrintMotd no" >> /etc/ssh/sshd_config && \
    echo "Port 22" >> /etc/ssh/sshd_config && \
    echo "ListenAddress 0.0.0.0" >> /etc/ssh/sshd_config

# Create working directory
WORKDIR /home/attacker/epirootkit

# Copy the attacking program
COPY attacking_program /home/attacker/epirootkit/attacking_program/

# Set permissions
RUN chown -R attacker:attacker /home/attacker/epirootkit

# Switch to non-root user
USER attacker

# Expose SSH port
EXPOSE 22

# Start SSH service
CMD ["sudo", "/usr/sbin/sshd", "-D"] 