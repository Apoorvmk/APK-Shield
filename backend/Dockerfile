FROM python:3.11-slim

# Install jadx and apktool dependencies
RUN apt-get update && apt-get install -y \
    default-jdk-headless \
    libmagic1 \
    wget \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Install apktool
RUN wget https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool \
    -O /usr/local/bin/apktool && chmod +x /usr/local/bin/apktool
RUN wget https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.9.3.jar \
    -O /usr/local/bin/apktool.jar

# Install jadx
RUN wget https://github.com/skylot/jadx/releases/download/v1.5.0/jadx-1.5.0.zip \
    -O /tmp/jadx.zip && unzip /tmp/jadx.zip -d /opt/jadx
ENV PATH="/opt/jadx/bin:$PATH"

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]