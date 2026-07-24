FROM rust:1.97-slim-trixie

ARG USERNAME=vscode 
ARG USER_UID=1000
ARG USER_GID=$USER_UID

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    bash \
    clang \
    cpio \
    curl \
    ca-certificates \
    git \
    less \
    libclang-dev \
    linux-image-cloud-amd64 \
    make \
    mtools \
    parted \
    qemu-system-arm \
    qemu-system-x86 \
    ssh \
    sudo \
    vim \
    xz-utils

RUN rustup component add clippy rustfmt



# Create the user
RUN groupadd --gid $USER_GID $USERNAME \
    && useradd --uid $USER_UID --gid $USER_GID -m $USERNAME -s /bin/bash \
    && echo $USERNAME ALL=\(root\) NOPASSWD:ALL > /etc/sudoers.d/$USERNAME \
    && chmod 0440 /etc/sudoers.d/$USERNAME

USER ${USERNAME}

# Setup antigravity
RUN curl -fsSL https://antigravity.google/cli/install.sh | bash
RUN bash && echo 'export PATH="/home/user/.local/bin:$PATH"' >> ~/.bashrc