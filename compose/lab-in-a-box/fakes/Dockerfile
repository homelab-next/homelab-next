# SPDX-License-Identifier: Apache-2.0
# The project's own fakes (fake inference server, fake case system) and the one-shot initialiser,
# in one small image.  Build context is the repository root:
#   docker build -f compose/lab-in-a-box/fakes/Dockerfile .
FROM python:3.15.0-slim-bookworm@sha256:0e019bbdfb5d9874cb2389f1c2884b64aa2ac97c99960b5bc521cef978c0617d
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
RUN useradd --system --uid 10001 --no-create-home lab
WORKDIR /app
COPY conformance/fakes/openai_server.py /app/openai_server.py
COPY compose/lab-in-a-box/fakes/fake_cases.py /app/fake_cases.py
COPY compose/lab-in-a-box/fakes/lab_init.py /app/lab_init.py
USER 10001
EXPOSE 8000
CMD ["python", "/app/openai_server.py", "--host", "0.0.0.0", "--allow-any-host", "--port", "8000"]
