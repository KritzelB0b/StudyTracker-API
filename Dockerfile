# A small reproducible image avoids the large Nixpacks/Railpack layers that
# stalled on the Railway registry image-push stage.
FROM python:3.12-slim-bookworm AS deps

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:${PATH}"
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt \
    && pip check

FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:${PATH}"
RUN groupadd --system --gid 10001 studytracker \
    && useradd --system --uid 10001 --gid 10001 --home-dir /app studytracker
COPY --from=deps /opt/venv /opt/venv
WORKDIR /app
COPY --chown=studytracker:studytracker main.py ical_subscription.py /app/
USER studytracker
EXPOSE 8080
CMD ["sh", "-c", "exec uvicorn main:app --host 0.0.0.0 --port ${PORT:-8080}"]
