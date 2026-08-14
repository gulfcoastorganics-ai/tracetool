# PNG to SVG Converter

A lightweight, browser-only PNG image tracer. Files are decoded, traced, sanitized, previewed, and downloaded locally; no server or API key is involved.

## Run locally

Requires Node.js 18+.

```sh
npm install
npm run dev
```

Open the local URL printed by Vite. Select or drop a PNG, adjust the trace settings, then choose **Convert to SVG** and **Download SVG**.

## Verify and build

```sh
npm test
npm run build
```

The app accepts PNGs up to 15 MB. It uses `imagetracerjs` for bitmap vectorization, with black-and-white and color modes, thresholding, detail/path omission, smoothing, color count, transparency, and inversion controls. Large source images are traced at a maximum working dimension of 1600 pixels to keep mobile and low-powered devices responsive while preserving the original aspect ratio in the SVG view box.

## Raster-to-vector limitations

Tracing approximates pixels with paths; it cannot recover the original design intent. Photographs, gradients, anti-aliased edges, and noisy images can produce many paths or an approximate result. Color tracing can be larger and slower than black-and-white tracing, and the working-size cap trades some detail for responsiveness.
# tracetool
