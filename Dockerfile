FROM python:3.13.14-slim

COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/

RUN groupadd -r secret_group && useradd -r -g secret_group --no-create-home --shell /bin/false secret_user

WORKDIR /app

RUN chown -R secret_user:secret_group /app

USER secret_user

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

COPY --chown=secret_user:secret_group "pyproject.toml" "uv.lock" ".python-version" ./

RUN uv sync --frozen --no-install-project --no-cache

COPY --chown=secret_user:secret_group bot.py .
RUN mkdir data

ENTRYPOINT ["python", "bot.py"]