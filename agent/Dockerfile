# Agent container. Agent runtimes commonly require linux/arm64 images listening on port 8080.
# Build from the repository root:  docker build --platform linux/arm64 -f agent/Dockerfile -t fli-agent .
FROM public.ecr.aws/docker/library/python:3.13-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY agent/requirements.txt agent/requirements.txt
RUN pip install --no-cache-dir -r agent/requirements.txt
COPY src/ src/
COPY queries/ queries/
COPY config/ config/
COPY agent/ agent/
RUN useradd --create-home --uid 10001 agent
USER agent
EXPOSE 8080
CMD ["python", "-m", "agent.app"]
