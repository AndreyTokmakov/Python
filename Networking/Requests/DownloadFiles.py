
import requests

def download_file(url: str, dest_file: str) -> None:
    with requests.get(url, stream=True) as response:
        response.raise_for_status()
        with open(dest_file, 'wb') as file:
            for chunk in response.iter_content(chunk_size=8192):
                file.write(chunk)



if __name__ == '__main__':
    url = 'http://i3.ytimg.com/vi/J---aiyznGQ/mqdefault.jpg'

    download_file(url, '/home/andtokm/Downloads/mqdefault.jpg')

