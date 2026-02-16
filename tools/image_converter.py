#!/usr/bin/env python3
import os
import argparse
from PIL import Image

def convert_image(input_image_path):
    output_dir = os.path.join(os.path.dirname(input_image_path), 'outputs')
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    with Image.open(input_image_path) as img:
        formats = ['PNG', 'JPEG', 'BMP', 'GIF', 'PDF', 'TIFF', 'WEBP', 'ICO', 'PCX', 'PPM']
        file_name = os.path.splitext(os.path.basename(input_image_path))[0]

        for fmt in formats:
            img_to_save = img
            if img.mode == 'RGBA':
                if fmt in ('JPEG', 'BMP', 'GIF', 'PDF', 'PCX', 'ICO', 'PPM', 'WEBP'):
                    img_to_save = img.convert('RGB')

            extra_params = {}
            if fmt == 'TIFF':
                extra_params['compression'] = 'tiff_lzw'
            elif fmt == 'JPEG':
                extra_params['quality'] = 95

            output_file_path = os.path.join(output_dir, f"{file_name}.{fmt.lower()}")
            img_to_save.save(output_file_path, fmt, **extra_params)
            print(f"Saved {output_file_path}")

def main():
    parser = argparse.ArgumentParser(description='Convert an image into multiple formats.')
    parser.add_argument('input_file', help='The path to the input image file.')

    args = parser.parse_args()
    convert_image(args.input_file)

if __name__ == "__main__":
    main()
