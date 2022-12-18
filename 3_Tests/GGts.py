from gtts import gTTS

if __name__ == '__main__':
    text = 'Привет Андрей'
    obj = gTTS(text, lang='ru')
    obj.save('/home/andtokm/DiskS/Temp/GTTS/Hello.mp3')