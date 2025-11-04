def obfuscate_data(data, key=b"VHS_KEY"):
    """
    XOR obfuscate/de-obfuscate a byte array.
    """
    if not data:
        return data
    key_stream = (key * (len(data) // len(key) + 1))[:len(data)]
    obfuscated_data = bytes(a ^ b for a, b in zip(data, key_stream))
    return obfuscated_data


def test_decrypt_file(input_encrypted_path, output_decrypted_path, key=b"VHS_KEY", length=1024):
    """
    Read an encrypted file, decrypt it using obfuscate_data, and write the result to a new file.
    """
    with open(input_encrypted_path, 'rb') as f:
        encrypted_data = f.read()

    decrypted_data = obfuscate_data(encrypted_data)

    with open(output_decrypted_path, 'wb') as f:
        f.write(decrypted_data)

    print(f"Decrypted file saved to: {output_decrypted_path}")


encrypted_file = "/Users/dinaqian/Downloads/ComfyUI_20251104_210417_Wan-2.2_I2V_00001.mp4"
decrypted_file = "/Users/dinaqian/Downloads/ComfyUI_20251104_210417_Wan-2.2_I2V_00001_de.mp4"
key = b"VHS_KEY"
length = 1024
test_decrypt_file(encrypted_file, decrypted_file, key=key, length=length)