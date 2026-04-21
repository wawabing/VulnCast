FROM public.ecr.aws/lambda/python:3.11

# Upgrade pip so it finds pre-built wheels
RUN pip install --upgrade pip

# Install dependencies (all use pre-built manylinux wheels — no compiler needed)
COPY requirements.txt ${LAMBDA_TASK_ROOT}/
RUN pip install --no-cache-dir --only-binary=numpy,pandas,scipy -r ${LAMBDA_TASK_ROOT}/requirements.txt

# Copy application code
COPY config.py ${LAMBDA_TASK_ROOT}/
COPY nvd_downloader.py ${LAMBDA_TASK_ROOT}/
COPY dynamo_client.py ${LAMBDA_TASK_ROOT}/
COPY forecast_engine.py ${LAMBDA_TASK_ROOT}/
COPY forecastability.py ${LAMBDA_TASK_ROOT}/
COPY handler.py ${LAMBDA_TASK_ROOT}/

# Lambda handler
CMD ["handler.lambda_handler"]
