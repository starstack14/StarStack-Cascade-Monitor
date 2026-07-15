from pathlib import Path
from PIL import Image, ImageDraw

out = Path(__file__).resolve().parent / "assets"
out.mkdir(exist_ok=True)
image = Image.new("RGBA", (256, 256), (16, 9, 15, 255))
draw = ImageDraw.Draw(image)
draw.rounded_rectangle((13, 13, 243, 243), radius=58, fill=(33, 16, 25, 255), outline=(255, 73, 61, 255), width=11)
draw.line((70, 170, 128, 70, 186, 170), fill=(255, 152, 61, 255), width=24, joint="curve")
draw.ellipse((107, 106, 149, 148), fill=(85, 230, 165, 255))
image.save(out / "starstack.ico", sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
