# ForensiX CLIP image encoder

The local model is installed at `models/vision/forensix_clip_image_encoder.onnx`.
It is not stored in Git. The Docker deployment mounts that directory read-only at
`/opt/forensix/models` and configures the media worker automatically.

## Verified artifact

| Field | Value |
| --- | --- |
| Architecture | OpenCLIP ViT-B-32 image encoder |
| Input | float32 NCHW, 224 x 224 RGB |
| Output | 512-dimensional L2-normalized embedding |
| SHA-256 | `5934fe73bce8d16a78ed10bacefe15bda2ca77a2c5609cf043ff09469d876153` |
| ONNX versus PyTorch maximum absolute error | `7.82310962677002e-08` |

The preprocessing contract is bicubic resize of the shortest image edge to 224,
center crop to 224 x 224, convert to RGB float values in `[0, 1]`, then normalize
using mean `[0.48145466, 0.4578275, 0.40821073]` and standard deviation
`[0.26862954, 0.26130258, 0.27577711]`. The media adapter applies this contract
when `FORENSIX_IMAGE_EMBEDDING_PREPROCESS=clip_openai`.

## Recorded evaluation

The supplied checkpoint was trained from random initialization for 10 epochs on
99,000 image-caption pairs, with 1,000 seeded held-out pairs. At the final epoch,
image-to-text Recall@1 was 0.7%, Recall@5 was 3.1%, and Recall@10 was 4.9%.
Text-to-image Recall@1 was 0.7%, Recall@5 was 2.7%, and Recall@10 was 6.2%.
The chance Recall@1 rate in that evaluation is 0.1%.

These measurements establish that the encoder is operating above the random
baseline, but they are not sufficient to represent it as high-accuracy semantic
retrieval. ForensiX records its vectors for within-case visual similarity; use
matches as review candidates and retain the original evidence as the source.

The imported proof artifacts are local-only under `models/vision/`: the model
metadata, metrics history, retrieval examples, and training proof plot.
