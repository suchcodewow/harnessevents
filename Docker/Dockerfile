FROM ubuntu:latest

SHELL ["/bin/bash", "-exo", "pipefail", "-c"]

LABEL maintainer="HarnessEvents <admin@harnessevents.io.>"
ENV DEBIAN_FRONTEND=noninteractive 

RUN	apt-get update && apt-get install -y  \
		apt-transport-https \
		autoconf \
		build-essential \
		ca-certificates \
		cmake \
		curl \
		elixir \
		gnupg \
		gzip \
		jq \
		libcurl4-openssl-dev \
		libmariadb-dev \
		libmariadb-dev-compat \
		libpq-dev \
		libsqlite3-dev \
		libssl-dev \
		lsb-release \
		make \
		net-tools \
		openssh-client \
		parallel \
		pkg-config \
		postgresql-client \
		python3 \
		python3-pip \
		shellcheck \
		software-properties-common \
		sudo \
		tar \
		tzdata \
		unzip \
		vim \
		wget \
		zip && \
	add-apt-repository ppa:git-core/ppa && apt-get install -y git && \
	wget -q https://packages.microsoft.com/config/ubuntu/16.04/packages-microsoft-prod.deb && \
	dpkg -i packages-microsoft-prod.deb && \
	apt-get update && apt-get install -y powershell && \
	echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | tee -a /etc/apt/sources.list.d/google-cloud-sdk.list && curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg && apt-get update -y && apt-get install google-cloud-cli -y && \
   	rm -rf /var/lib/apt/lists/*
# RUN add-apt-repository ppa:git-core/ppa && apt-get install -y git && \
# 	rm -rf /var/lib/apt/lists/*
# RUN wget -q https://packages.microsoft.com/config/ubuntu/16.04/packages-microsoft-prod.deb && \
# 		dpkg -i packages-microsoft-prod.deb && \
# 		apt-get update && apt-get install -y powershell
# RUN echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | tee -a /etc/apt/sources.list.d/google-cloud-sdk.list && curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg && apt-get update -y && apt-get install google-cloud-cli -y
    