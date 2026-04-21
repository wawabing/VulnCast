FROM public.ecr.aws/lambda/python:3.12

# Upgrade pip first
RUN pip install --upgrade pip

COPY requirements.txt .
RUN pip install --no-cache-dir --only-binary=numpy,pandas,scipy,xgboost,scikit-learn -r requirements.txt

COPY config.py handler.py forecast_engine.py nvd_downloader.py ./

CMD ["handler.lambda_handler"]
