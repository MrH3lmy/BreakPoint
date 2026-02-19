FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv \
    aircrack-ng hcxdumptool hashcat \
    gpsd gpsd-clients \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip3 install --no-cache-dir -r requirements.txt

COPY . .
CMD ["python3", "main_cli.py"]
