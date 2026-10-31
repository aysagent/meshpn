FROM localhost/meshpn-clean-vpn-lab:1f35b200e5e912e7
USER root
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends gawk rsync unzip wget file libncurses-dev && rm -rf /var/lib/apt/lists/*
RUN dpkg-query -W gawk rsync unzip wget file libncurses-dev
