Usually, we use UI framework-specific tools for UI test automation, these tools provide hooks and bindings for underlying
technology and make it easier to interact with an application. However sometimes these tools don't cover
everything that we are interested in and there is still a need for raw image analysis. We propose you to work on
an exercise that is a little artificial, but perfectly maps to challenges you might experience in day-to-day routine.

There is a `circlemaker.py` command line application that generates a circle on a 400x400px canvas with a 1px border
around it. Size and color of the circle can be set via command line arguments, thickness of the border is fixed and
cannot be changed, however color of the border is random and changes on every application launch. Please write
automated tests that prove that circle size and color on the generated image changes according to the arguments
passed via command line.

If, in your opinion, something is missing from the description, and you are making additional assumptions while creating
tests, please, let us know about them when you send us the solution.

To launch the app:

   1. Install dependencies:
     
```shell script
pip install -r requirements.txt
   ```     
   
   2. Run the app:
   
```shell script
python3 circlemaker.py -d 89 -hue 89 -path test.png
   ```
where:
 
- `-d` - diameter of the circle
- `-hue` - Hue component of the HSV color (Saturation and Value of the color are always 100%)
- `-path` - output path of the generated image
