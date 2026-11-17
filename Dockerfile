FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir uv

COPY pyproject.toml README.md LICENSE ./
COPY *.py ./
COPY assets ./assets
COPY blender_addon ./blender_addon
COPY docs ./docs
COPY presets ./presets
COPY ui ./ui
COPY tests ./tests
COPY COOP_SKILL.md .env.example apps.example.json ./

RUN uv pip install --system --no-cache ".[dev]"

EXPOSE 8089

CMD ["python", "tests/run_all.py"]
