from PIL import Image
from PIL.ExifTags import TAGS
from modules.gps import extract_gps


def extract_metadata(image_path):
    """
    Extract EXIF metadata from an image.

    Args:
        image_path (str): Path to the image.

    Returns:
        dict: Metadata with readable EXIF tag names.
    """

    metadata = {}

    try:
       
        image = Image.open(image_path)
        exif_data = image.getexif()
        if not exif_data:
            return metadata

        gps = extract_gps(exif_data)

        if gps:
            metadata["Latitude"] = gps["Latitude"]
            metadata["Longitude"] = gps["Longitude"]
            metadata["Google Maps"] = gps["Google Maps"]

        for tag_id, value in exif_data.items():

            tag_name = TAGS.get(tag_id, tag_id)
            
            if isinstance(value, bytes):
             continue
            if tag_name == "GPSInfo":
                continue

            metadata[tag_name] = value

        return metadata

    except Exception as e:
        raise Exception(f"Error extracting metadata: {e}")