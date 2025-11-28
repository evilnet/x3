FROM debian:12

ENV GID=1234
ENV UID=1234

RUN DEBIAN_FRONTEND=noninteractive RUNLEVEL=1 apt-get update 
RUN DEBIAN_FRONTEND=noninteractive RUNLEVEL=1 apt-get update && apt-get -y install build-essential libssl-dev autoconf2.69 automake1.11 flex byacc gawk git vim procps net-tools libtre5 libtre-dev

RUN mkdir -p /x3
RUN mkdir -p /x3/x3src
COPY . /x3/x3src

RUN groupadd -g ${GID} x3
RUN useradd -u ${UID} -g ${GID} x3
RUN chown -R x3:x3 /x3
USER x3

WORKDIR  /x3/x3src

#RUN ./autogen.sh
RUN ./configure --prefix=/x3 --sysconfdir=/x3/data --enable-modules=snoop,memoserv,helpserv

RUN make
RUN make install
WORKDIR /x3

USER root
#Clean up build
#RUN apt-get remove -y build-essential && apt-get autoremove -y
#RUN apt-get clean
RUN mkdir -p /x3/data && chown x3:x3 /x3/data

USER x3

#COPY docker/x3.conf-dist /x3/data/x3.conf-dist
COPY docker/dockerentrypoint.sh /dockerentrypoint.sh

ENTRYPOINT ["/dockerentrypoint.sh"]

CMD ["/x3/bin/x3", "-c", "/x3/data/x3.conf", "-f", "-d"]

