FROM python:3

ADD sniff_extract3.py /

RUN pip install scp
RUN pip install paramiko

RUN pip install --default-timeout=200 numpy
RUN pip install --default-timeout=200 pandas
RUN pip install scapy
RUN pip install datetime

CMD ["python3", "sniff_extract3.py"]
