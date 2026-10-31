FROM scratch AS sources
COPY protocol/ /scanner/protocol/
COPY src/ /scanner/src/
COPY policies/ /scanner/policies/

FROM python:3.13-slim-bookworm AS policy
RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /scanner
COPY --from=sources /scanner /scanner
ENV PYTHONPATH=/scanner/src PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 HOME=/tmp
USER 65532:65532
ENTRYPOINT ["python", "-m", "bypass_scanner"]

FROM node:24-bookworm-slim AS node
FROM golang:1.26-bookworm AS go
FROM rust:1.99.0-bookworm AS rust
FROM mcr.microsoft.com/dotnet/sdk:8.0.415-bookworm-slim AS dotnet
FROM python:3.13-slim-bookworm
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules /usr/local/lib/node_modules
COPY --from=go /usr/local/go /usr/local/go
COPY --from=rust /usr/local/cargo /usr/local/cargo
COPY --from=rust /usr/local/rustup /usr/local/rustup
COPY --from=dotnet /usr/share/dotnet /usr/share/dotnet
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl zstd unzip git build-essential cmake ninja-build \
    openjdk-17-jdk-headless maven ruby libicu72 libunwind8 \
    && rm -rf /var/lib/apt/lists/* \
    && ln -s ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
    && ln -s ../lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx \
    && ln -s /usr/share/dotnet/dotnet /usr/local/bin/dotnet
WORKDIR /scanner
COPY codeql-lock.json ./codeql-lock.json
RUN python -c 'import json,subprocess; c=json.load(open("codeql-lock.json")); subprocess.run(["curl","--fail","--location","--retry","3",c["bundleUrl"],"-o","/tmp/codeql.tar.zst"],check=True); subprocess.run(["sha256sum","-c"],input=c["bundleSha256"]+"  /tmp/codeql.tar.zst\n",text=True,check=True); subprocess.run(["tar","--zstd","-xf","/tmp/codeql.tar.zst","-C","/opt"],check=True)' \
    && rm /tmp/codeql.tar.zst
RUN python -c 'import json,subprocess; c=json.load(open("codeql-lock.json")); v=c["kotlinVersion"]; subprocess.run(["curl","--fail","--location","--retry","3",f"https://github.com/JetBrains/kotlin/releases/download/v{v}/kotlin-compiler-{v}.zip","-o","/tmp/kotlin.zip"],check=True); subprocess.run(["sha256sum","-c"],input=c["kotlinSha256"]+"  /tmp/kotlin.zip\n",text=True,check=True); subprocess.run(["unzip","-q","/tmp/kotlin.zip","-d","/opt"],check=True)' \
    && rm /tmp/kotlin.zip
ENV PATH="/opt/codeql:/opt/kotlinc/bin:/usr/local/go/bin:/usr/local/cargo/bin:${PATH}" \
    JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64 RUSTUP_HOME=/usr/local/rustup \
    DOTNET_ROOT=/usr/share/dotnet DOTNET_CLI_TELEMETRY_OPTOUT=1 \
    PYTHONPATH=/scanner/src PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    BYPASS_CODEQL=/opt/codeql/codeql HOME=/tmp
RUN rustup component add rust-src
COPY --from=sources /scanner /scanner
RUN python -m bypass_scanner.discovery.catalog \
    && python -c 'import json,subprocess; p={x:subprocess.run(a,capture_output=True,text=True).stdout.strip() for x,a in {"node":["node","--version"],"go":["go","version"],"rust":["rustc","--version"],"dotnet":["dotnet","--version"],"python":["python","--version"]}.items()}; open("/opt/bypass-toolchains.json","w").write(json.dumps(p))' \
    && chmod -R a+rX /scanner /opt/codeql /opt/bypass-codeql-catalog.json /opt/bypass-toolchains.json
USER 65532:65532
ENTRYPOINT ["python", "-m", "bypass_scanner"]
