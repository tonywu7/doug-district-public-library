import colorsys
import re
import sys
from PIL import ImageColor

if __name__ == '__main__':
    HEX = re.compile(r'- \!\[(#[0-9a-f]+)\]')
    text = sys.stdin.read().split('\n')
    matched = [(HEX.match(line), line) for line in text]
    colors = sorted((colorsys.rgb_to_hsv(*ImageColor.getrgb(c[1])), line) for c, line in matched if c)
    print()
    for hsv, line in colors:
        print(line)
