from PIL.ExifTags import GPSTAGS


def extract_gps(exif_data):
    """
    Extract GPS coordinates from EXIF data.
    """

    try:
        gps_info = exif_data.get_ifd(34853)

    except KeyError:
        return None


    gps_data = {}

    for key, value in gps_info.items():
        gps_data[GPSTAGS.get(key, key)] = value


    required = (
        "GPSLatitude",
        "GPSLatitudeRef",
        "GPSLongitude",
        "GPSLongitudeRef",
    )


    if not all(tag in gps_data for tag in required):
        return None


    latitude = convert_to_degrees(
        gps_data["GPSLatitude"]
    )

    longitude = convert_to_degrees(
        gps_data["GPSLongitude"]
    )


    
    if latitude is None or longitude is None:
        return None


    if gps_data["GPSLatitudeRef"] == "S":
        latitude = -latitude


    if gps_data["GPSLongitudeRef"] == "W":
        longitude = -longitude


    return {
        "Latitude": latitude,
        "Longitude": longitude,
         "Google Maps": f"https://maps.google.com/?q={latitude},{longitude}"
    }



def convert_to_degrees(value):
    """
    Convert GPS coordinates from DMS format
    to decimal degrees.
    """

    try:
        degrees = float(value[0])
        minutes = float(value[1])
        seconds = float(value[2])

    except (ValueError, TypeError):
        return None


   
    if (
        degrees != degrees or
        minutes != minutes or
        seconds != seconds
    ):
        return None


    return degrees + (minutes / 60) + (seconds / 3600)