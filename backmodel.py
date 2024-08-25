from fastapi import FastAPI
from detection import predict_new_url
from pydantic import BaseModel

app = FastAPI()

class PredictData(BaseModel):
    option: str
    url: str

@app.get("/")
def read_root():
       return {"message": "Welcome to the ML Model API"}


@app.post("/predict")

def predict(request: PredictData):
    result = predict_new_url(request.option, request.url)
    return result