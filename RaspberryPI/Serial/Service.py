
import schedule
import serial

# speech speak
from rhvoice_wrapper import TTS
import subprocess
from time import sleep


### языковая часть
def say(text):
    data = tts.get(text, format_='wav')
    # print('data size: ', len(data), ' bytes')
    subprocess.check_output(['aplay', '-r', '16000', '-q'], input=data)


tts = TTS(threads=1)


# python -m serial.tools.list_ports
# ser = serial.Serial("/dev/ttyS0",baudrate=9600,timeout=0.1)

def func():
    """open serial every ___ min and check voltage drop"""
    ser = serial.Serial("/dev/ttyUSB0", baudrate=9600, timeout=0.1)
    ser.flush()
    # print(ser)

    while True:
        try:
            line = ser.readline().decode().strip()
            if line:
                print(line.split(' ')[7].strip('V'))
                if float(line.split(' ')[7].strip('V')) > 0.5:
                    print('разряжено')
                    # say('разряжено')
                    ser.close()
                    return False
        except Exception as exc:
            print(exc)
            pass

    # ser.close()


if __name__ == "__main__":
    schedule.every(1).minutes.do(func)

    while True:
        schedule.run_pending()
        sleep(1)