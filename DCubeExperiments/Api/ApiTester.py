from typing import Dict
import requests


class DCubeApiClient(object):

    def __init__(self, url: str):
        self.INTERNAL_API_ENDPOINT = "/internal/api/"
        self.JOB_ENDPOINT = "job/"
        self.FIRMWARE_ENDPOINT = "firmware/"
        self.LAYOUT_ENDPOINT = "layout/"
        self.JAMMING_ENDPOINT = "jamming/"
        self.PATCH_ENDPOINT = "patch/"
        self.CUSTOM_PATCH_ENDPOINT = "patch/custom/"
        self.TEMPLAB_ENDPOINT = "templab/"

        self.url = url

    def get_job(self, job_id: int):
        jod_endpoint = f'{self.url}{self.INTERNAL_API_ENDPOINT}{self.JOB_ENDPOINT}{job_id}'  # TODO: Refactor
        response = requests.get(jod_endpoint)
        if 200 == response.status_code:  # HTTP_OK
            data: Dict = response.json()
            print(data)
        else:
            print(f"Error {response.status_code}")


if __name__ == '__main__':
    api = DCubeApiClient("http://127.0.0.1:8888")
    api.get_job(3)


