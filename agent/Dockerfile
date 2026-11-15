# Agent container. Agent runtimes commonly require linux/arm64 images listening on port 8080.
# Build from the repository root:  docker build --platform linux/arm64 -f agent/Dockerfile -t fli-agent .
FROM public.ecr.aws/docker/library/python:3.13-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
# Take the base image's pending security fixes, then install pinned dependencies under patched constraints.
RUN apt-get update && apt-get -y upgrade && rm -rf /var/lib/apt/lists/*
COPY agent/requirements.txt agent/constraints.txt agent/
RUN pip install --no-cache-dir -c agent/constraints.txt -r agent/requirements.txt \
    && pip install --no-cache-dir -c agent/constraints.txt --upgrade setuptools
COPY src/ src/
COPY queries/ queries/
COPY config/ config/
COPY agent/ agent/
RUN useradd --create-home --uid 10001 agent
USER agent
EXPOSE 8080
CMD ["python", "-m", "agent.app"]
