FROM ubuntu:24.10

SHELL ["/bin/bash", "-exo", "pipefail", "-c"]

LABEL maintainer="HarnessEvents <admin@harnessevents.io.>"
ENV DEBIAN_FRONTEND=noninteractive 

RUN apt-get update && apt-get install -y elixir
# RUN noInstallRecommends="" && \
# 	if [[ "22.04" == "22.04" ]]; then \
# 		noInstallRecommends="--no-install-recommends"; \
# 	fi && \ 
# 	apt-get update && apt-get install -y $noInstallRecommends \
# 	    elixir \
# 		autoconf \
# 		build-essential \
# 		ca-certificates \
# 		cmake \
# 		# already installed but here for consistency
# 		curl \
# 		gnupg \
# 		gzip \
# 		jq \
# 		libcurl4-openssl-dev \
# 		# popular DB lib - MariaDB
# 		libmariadb-dev \
# 		# allows MySQL users to use MariaDB lib
# 		libmariadb-dev-compat \
# 		# popular DB lib - PostgreSQL
# 		libpq-dev \
# 		libssl-dev \
# 		libsqlite3-dev \
# 		make \
# 		python3 \
# 		# for ssh-enabled builds
# 		net-tools \
# 		netcat \
# 		openssh-client \
# 		parallel \
# 		# compiling tool
# 		pkg-config \
# 		postgresql-client \
# 		shellcheck \
# 		software-properties-common \
# 		# already installed but here for consistency
# 		sudo \
# 		tar \
# 		tzdata \
# 		unzip \
# 		python3-pip \
# 		# for ssh-enabled builds
# 		vim \
# 		wget \
	# 	zip && \
	# add-apt-repository ppa:git-core/ppa && apt-get install -y git && \
	# rm -rf /var/lib/apt/lists/*