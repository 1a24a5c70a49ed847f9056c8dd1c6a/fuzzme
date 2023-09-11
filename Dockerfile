FROM debian:11

# install tools
RUN apt-get update
RUN apt-get install -y curl

SHELL ["/bin/bash", "--login", "-c"]

ENV NODE_VERSION=18.13.0
ENV NVM_DIR /tmp/nvm
WORKDIR $NVM_DIR
# install node.js
RUN curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.5/install.sh | bash \
	&& . $NVM_DIR/nvm.sh \
	&& nvm install 18.13.0


RUN mkdir /fuzzme
WORKDIR /fuzzme
RUN npm install html-entities
COPY server.js .
COPY data.js .
CMD node server.js 0.0.0.0 1337
