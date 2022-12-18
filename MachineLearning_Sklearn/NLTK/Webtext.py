
import nltk

from nltk.corpus import webtext
from nltk.corpus import nps_chat

# INFO: https://www.nltk.org/book/ch02.html

if __name__ == '__main__':
    # nltk.download('webtext')
    # nltk.download('nps_chat')

    for fileid in webtext.fileids():
        print(fileid, webtext.raw(fileid)[:65], '...')

    print('==================================================================')

    chatroom = nps_chat.posts('10-19-20s_706posts.xml')
    print(chatroom[123])