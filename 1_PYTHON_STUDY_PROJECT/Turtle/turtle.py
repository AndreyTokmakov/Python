import turtle

if __name__ == '__main__':
    for i in range(0, 10):
        turtle.right(36)
        for i in range(0, 5):
            turtle.forward(100)
        turtle.right(72)
        
    turtle.exitonClick()