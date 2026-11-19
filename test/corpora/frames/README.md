# Encoded video for the frame buffer tests

Twelve frames of ffmpeg's `testsrc`, a key frame every six, made with:

```sh
ffmpeg -f lavfi -i testsrc=size=176x144:rate=30 -frames:v 12 -c:v libvpx -g 6 -b:v 100k vp8.ivf
ffmpeg -f lavfi -i testsrc=size=176x144:rate=30 -frames:v 12 -pix_fmt yuv420p -c:v libvpx-vp9 -g 6 -b:v 100k vp9.ivf
ffmpeg -f lavfi -i testsrc=size=174x130:rate=30 -frames:v 12 -pix_fmt yuv420p -c:v libx264 -profile:v baseline -g 6 -bf 0 -b:v 100k -f h264 h264.h264
ffmpeg -f lavfi -i testsrc=size=176x144:rate=30 -frames:v 12 -c:v libsvtav1 -g 6 -b:v 100k -pix_fmt yuv420p av1.ivf
```

`-pix_fmt yuv420p` keeps VP9 in profile 0 (4:2:0), the profile browsers send and the one we offer (`profile-id=0`); `testsrc` is RGB, and without it libvpx encodes 4:4:4 in profile 1. The H.264 size is not a multiple of 16, so its SPS crops. `webrtc_test_frames` reads them.
