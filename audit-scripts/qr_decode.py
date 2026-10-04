import cv2, os, numpy as np

P = r"C:\Users\adversary\Desktop\RevEng\DrNeelanjanMannaDortressTechnologiesPrivateLimitedTestingPasswordis123\a.png"
img = cv2.imread(P, cv2.IMREAD_GRAYSCALE)
print("shape", img.shape, "min/max", img.min(), img.max())
# upscale for robust detection
big = cv2.resize(img, None, fx=4, fy=4, interpolation=cv2.INTER_NEAREST)
det = cv2.QRCodeDetector()
for name, im in (("orig", img), ("big", big)):
    data, pts, _ = det.detectAndDecode(im)
    print(f"--- {name} ---")
    print(repr(data))
    print("pts:", None if pts is None else pts.astype(int).tolist())
