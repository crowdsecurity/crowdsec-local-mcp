
FROM ubuntu:24.04

# Install dependencies
RUN apt-get update && apt-get install -y \
    git \
    make \
    software-properties-common \
    wget \
    gnupg \
    ca-certificates \
    gettext \
    curl

RUN wget -O - https://openresty.org/package/pubkey.gpg | apt-key add -
RUN echo "deb http://openresty.org/package/ubuntu $(lsb_release -sc) main"| tee /etc/apt/sources.list.d/openresty.list
RUN curl -s https://install.crowdsec.net |  bash

RUN apt update

RUN apt install -y openresty openresty-opm gettext-base

RUN apt install -y crowdsec-openresty-bouncer



EXPOSE 80


# # Install the bouncer
# COPY build.sh /build.sh
# COPY start.sh /start.sh

# RUN chmod +x /build.sh && /build.sh
# RUN chmod +x /start.sh

# # Set the script as the entrypoint
# ENTRYPOINT ["/start.sh"]



# FROM debian:bookworm

# ENV DEBIAN_FRONTEND=noninteractive

# # Install nginx with Lua module support and prerequisites for the CrowdSec nginx bouncer.
# RUN set -eux; \
#     apt-get update; \
#     apt-get install -y --no-install-recommends \
#         ca-certificates \
#         curl \
#         gnupg2 \
#         iproute2 \
#         libnginx-mod-http-lua \
#         lsb-release \
#         nginx \
#         procps; \
#     curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | bash; \
#     apt-get install -y --no-install-recommends crowdsec-nginx-bouncer; \
#     rm -rf /var/lib/apt/lists/*

# # Prepare directories that will receive bind mounts at runtime.
# RUN mkdir -p /etc/nginx/conf.d /etc/nginx/crowdsec

# EXPOSE 80

# CMD ["nginx", "-g", "daemon off;"]
