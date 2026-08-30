from pathlib import Path
from PIL import Image


SUPPORTED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".bmp", ".tiff"}


def validate_image(image_path):


    print('ENTER to THE function -------')
    """
    Validate that the provided path points to a supported and readable image.

    Args:
        image_path (str): Path to the image file.

    Returns:
        bool: True if the image is valid.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the extension is not supported.
        OSError: If the file cannot be opened as an image.
    """

    image = Path(image_path)

    if not image.exists():
        raise FileNotFoundError(f"File not found: {image_path}")

    
    if not image.is_file():
        raise FileNotFoundError(f"'{image_path}' is not a file.")

    
    if image.suffix.lower() not in SUPPORTED_EXTENSIONS:
        raise ValueError(
            f"Unsupported image format '{image.suffix}'. "
            f"Supported formats: {', '.join(SUPPORTED_EXTENSIONS)}"
        )
    
    try:
        with Image.open(image) as img:
            img.verify()
    except Exception as e:
        raise OSError(f"Invalid or corrupted image: {e}")

    return True