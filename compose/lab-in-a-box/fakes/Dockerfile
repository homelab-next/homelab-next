# SPDX-License-Identifier: Apache-2.0
# The project's own fakes (fake inference server, fake case system) and the one-shot initialiser,
# in one small image.  Build context is the repository root:
#   docker build -f compose/lab-in-a-box/fakes/Dockerfile .
FROM python:3.12-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
RUN useradd --system --uid 10001 --no-create-home lab
WORKDIR /app
COPY conformance/fakes/openai_server.py /app/openai_server.py
COPY compose/lab-in-a-box/fakes/fake_cases.py /app/fake_cases.py
COPY compose/lab-in-a-box/fakes/lab_init.py /app/lab_init.py
USER 10001
EXPOSE 8000
CMD ["python", "/app/openai_server.py", "--host", "0.0.0.0", "--allow-any-host", "--port", "8000"]
