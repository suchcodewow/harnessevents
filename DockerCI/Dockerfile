# docker buildx build --platform linux/amd64 -t suchcodewow/harnessevents:latest ./DockerCI
# docker push suchcodewow/harnessevents:latest
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
	curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip" && \
	unzip awscliv2.zip && \
	./aws/install && \
	wget -q https://packages.microsoft.com/config/ubuntu/16.04/packages-microsoft-prod.deb && \
	dpkg -i packages-microsoft-prod.deb && \
	mkdir -p /etc/apt/keyrings && \
    curl -sL https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor | sudo tee /etc/apt/keyrings/microsoft.gpg > /dev/null && \
	AZ_REPO=$(lsb_release -cs) && \
    echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/microsoft.gpg] https://packages.microsoft.com/repos/azure-cli/ $AZ_REPO main" | sudo tee /etc/apt/sources.list.d/azure-cli.list && \
	apt-get update && apt-get install -y powershell azure-cli && \
	echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | tee -a /etc/apt/sources.list.d/google-cloud-sdk.list && curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg && apt-get update -y && apt-get install google-cloud-cli -y && \
	curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" && \
	install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl && \
	apt-get install google-cloud-cli-gke-gcloud-auth-plugin -y && \
   	rm -rf /var/lib/apt/lists/*
