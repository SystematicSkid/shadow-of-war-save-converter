# Shadow of War Save Converter
Used to convert Shadow of War save files between different steam profiles.# Shadow of War Save File Decryptor/Encryptor 🔐

A Python utility for decrypting and re-encrypting Shadow of War save files. This tool allows you to process save files between different platforms (e.g., Steam to GOG) by handling the encryption/decryption process with different keys.

## 🌟 Features

- Decrypt save files using Steam/GOG keys
- Re-encrypt save files with new keys
- Automatic key detection from filenames
- Support for both hexadecimal and decimal key inputs
- Robust error handling and validation
- Cross-platform compatibility

## 📋 Requirements

- Python 3.6+
- PyCrypto library

Install the required dependency using pip:

```bash
pip install -r requirements.txt
```

## 🚀 Usage

### Basic Usage

```bash
python convert.py input_file.sav --new-id STEAM3_ID
```

The script will attempt to infer the steamid3 from the filename if it follows the format: `xxxxxxxx_ShadowOfWar.sav` (where `xxxxxxxx` is the hex key).

### Advanced Usage

You can explicitly specify both original steamid and new steamid:

```bash
python convert.py input_file.sav --decrypt-key KEY1 --new-id KEY2
```

Keys can be specified in either:
- Hexadecimal format (with `0x` prefix): `--decrypt-key 0x5fe91ade`
- Decimal format: `--decrypt-key 1609112286`

### GOG Usage
All GOG saves have an id of `0x00000000`. To decrypt a GOG save, use the following command:

```bash
python convert.py input_file.sav --decrypt-key 0x00000000 --new-id NEW_KEY
```

In order to run the save, the file name prefix must be the name of your computer.
### Examples

```bash
# Using filename for decrypt key
python convert.py 5fe91ade_ShadowOfWar.sav --new-id 0x5feeb44e

# Explicitly specifying both keys
python convert.py savefile.sav --original-id 0x5fe91ade --new-id 0x5feeb44e

# Using decimal values
python convert.py savefile.sav --original-id 1609112286 --new-id 1609112286
```

## 📁 Output Files

The script generates two files:
1. `decrypted_save.sav` - The intermediate decrypted save file, optional if using `--dump` flag
2. `[NEW_KEY]_ShadowOfWar.sav` - The re-encrypted save file with the new key

## 🔧 How It Works

1. **Key Detection**: The script first tries to detect the decryption key from the filename if not explicitly provided
2. **Decryption**: Uses AES-CBC-256 to decrypt the save file with the specified/detected key
3. **Re-encryption**: Re-encrypts the save data with the new key
4. **Output**: Generates both decrypted and re-encrypted versions of the save file

## 🛠️ Technical Details

- Uses AES-CBC-256 encryption
- Save files contain a 16-byte header with:
  - Magic number ("SOM3")
  - Key data
  - File length
  - Decrypted length

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 🐛 Known Issues

- None currently reported

---

*Note: This tool is not affiliated with or endorsed by the creators of Shadow of War.*