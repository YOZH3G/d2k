import sys
from PIL import Image, ImageDraw
d, prefix, start, out = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
names="rutracker fost nnmclub fast-torrent lostfilm kinozal bible-center numista rua.gr enimerosi romfea katzauction spzh flibusta web.facebook adguard mailsuite cloudflare speed.cf".split()
W,H=560,360; cols=5
sheet=Image.new('RGB',(W*cols,(H+24)*4),'white'); dr=ImageDraw.Draw(sheet)
for k in range(19):
    try: im=Image.open(f"{d}/{prefix}{k+start}.png").convert('RGB')
    except Exception: continue
    im.thumbnail((W,H)); x=(k%cols)*W; y=(k//cols)*(H+24)
    sheet.paste(im,(x,y+24)); dr.text((x+4,y+4),f"{k+1} {names[k]}",fill='black')
sheet.save(out)
