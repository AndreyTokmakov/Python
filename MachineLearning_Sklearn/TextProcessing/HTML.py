import lxml
from bs4 import BeautifulSoup

if __name__ == '__main__':
    html = """
        <div class='full_name'Xspan style='font-weight:bold'>
        Masego</span> Azra</div>"
        """

    soup = BeautifulSoup(html, "lxml")

    # Find the div element with the "full_name" class, show the text
    result = soup.find("div", {"class": "full_name"}).text

    print(result)
