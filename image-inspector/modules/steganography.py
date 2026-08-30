from PIL import Image

def extract_lsb_bits(image_path):
    
    """
    Extract the Least Significant Bit (LSB) from every RGB channel.

    Args:
        image_path (str): Path to the image.

    Returns:
        list: A list containing only 0s and 1s.
    """

    print("extract lbs bits -----*")
    
    bits = []
    
    try:
        print("test")
        image = Image.open(image_path)
        image = image.convert("RGB")
        for pix in image.getdata():
            r, g, b = pix
            bits.append(r & 1)
            bits.append(g & 1)
            bits.append(b & 1)
            
        return bits
            
    except Exception as e:
        raise Exception(f"Error extracting LSB bits: {e}") 


def bits_to_bytes(bits):
    """
    Convert a list of bits into a list of bytes.

    Args:
        bits (list): List containing 0s and 1s.

    Returns:
        list: List of integers (0-255).
    """

    bytes_list = []

    for i in range(0, len(bits), 8):

        byte = bits[i:i + 8]
        if len(byte) < 8:
            break

        value = 0
        for bit in byte:
            value = (value << 1) | bit

        bytes_list.append(value)

    return bytes_list

def bytes_to_text(bytes_list):
    """
    Convert a list of byte values into a text string.

    Args:
        bytes_list (list): List of integers (0-255).

    Returns:
        str: Decoded text.
    """

    try:
        text = bytes(bytes_list).decode("utf-8", errors="ignore")
        return text

    except Exception as e:
        raise Exception(f"Error converting bytes to text: {e}")

def detect_pgp_key(text):
    """
    Search for a PGP public key block.

    Args:
        text (str): Decoded text extracted from the image.

    Returns:
        str | None: The PGP block if found, otherwise None.
    """

    begin = "-----BEGIN PGP PUBLIC KEY BLOCK-----"
    end = "-----END PGP PUBLIC KEY BLOCK-----"

    start = text.find(begin)

    if start == -1:
        return None

    finish = text.find(end, start)

    if finish == -1:
        return None

    finish += len(end)

    return text[start:finish]