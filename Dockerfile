FROM ubuntu:latest
WORKDIR /
RUN apt-get update
RUN apt-get -y install automake libtool make gcc pkg-config python3-dev python3-pip wget libssl-dev git clamav clamav-daemon vim nano
# Setting up Yara for Yara-Python
RUN wget https://github.com/VirusTotal/yara/archive/refs/tags/v4.3.0.tar.gz
RUN tar -zxf v4.3.0.tar.gz
WORKDIR /yara-4.3.0
RUN ./bootstrap.sh
RUN ./configure
RUN make
RUN make install
RUN make check
#Installing the python pip packages
WORKDIR /
RUN python3 -m pip install --upgrade pip
COPY requirements.txt requirements.txt
RUN /usr/local/bin/pip install install -r requirements.txt
#yara-python setup
RUN git clone --recursive https://github.com/VirusTotal/yara-python
WORKDIR /yara-python
RUN python3 setup.py build
RUN python3 setup.py install
WORKDIR /
#Fetching the newest ClamAV signatures
RUN freshclam
#Copying the contents of the build folder into the Docker Container
COPY . .
#Ensuring that the setup Script can be run
RUN chmod +x setup.sh
#Mounting the folder to scan to a specific directory in the docker container
ADD ./detection/scanHere/* /filesToScan/
#Executing the script to start the program
CMD [ "/bin/bash","-c","./setup.sh"]