def save_output(data, filename, append=False):
    """
    Save metadata or steganography results to a text file.

    Args:
        data (dict | str): Data to save.
        filename (str): Output file name.
        append (bool): Append to the file instead of overwriting it.
    """

    mode = "a" if append else "w"

    try:
        with open(filename, mode, encoding="utf-8") as file:

            if isinstance(data, dict):
                for key, value in data.items():
                    file.write(f"{key}: {value}\n")
            else:
                file.write(str(data) + "\n")

        print(f"Data saved in {filename}")

    except Exception as e:
        raise Exception(f"Error saving output: {e}")