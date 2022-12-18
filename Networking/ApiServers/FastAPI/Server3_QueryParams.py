from fastapi import FastAPI
import uvicorn

app = FastAPI()


@app.get("/")
def read_root():
    return {"Hello": "World"}


@app.get("/api/v1/")
async def read_item(skip: int = 0,
                    first_name: str = "Jonh",
                    second_name: str = "Dow",
                    age: int = 18):
    return {"First name": first_name, "Second name": second_name, "age": age}


if __name__ == '__main__':
    uvicorn.run(app, host="0.0.0.0", port=52525, log_level="debug")
