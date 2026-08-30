from PIL import Image


def text_to_bits(text):
    """
    Convert text to a binary string.
    """
    return ''.join(format(ord(char), '08b') for char in text)


def hide_message(input_image, output_image, message):
    # Add a unique end marker so we know where the message ends
    message += "###END###"

    bits = text_to_bits(message)

    image = Image.open(input_image).convert("RGB")
    pixels = list(image.getdata())

    bit_index = 0
    new_pixels = []

    for pixel in pixels:
        r, g, b = pixel

        rgb = [r, g, b]

        for i in range(3):
            if bit_index < len(bits):
                # Clear the LSB then replace it
                rgb[i] = (rgb[i] & ~1) | int(bits[bit_index])
                bit_index += 1

        new_pixels.append(tuple(rgb))

    if bit_index < len(bits):
        raise ValueError("Message is too large for this image.")

    image.putdata(new_pixels)
    image.save(output_image)

    print(f"Hidden {bit_index} bits.")
    print(f"Saved as {output_image}")


if __name__ == "__main__":
    hide_message(
        input_image="../local.jpg",
        output_image="../hidden.png",
        message="""-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: Test

Hello Mustapha

-----END PGP PUBLIC KEY BLOCK-----"""
    )