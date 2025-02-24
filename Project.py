import time
import hashlib
def simulate_crack_time(key, method="brute-force"):
    print("Simulating cracking time...")
    if method == "brute-force":
        key_bits = len(key) * 8
        attempts = 2**key_bits
        time_per_attempt = 0.000001  # 1 microsecond
        estimated_time = attempts * time_per_attempt
        print(f"Estimated cracking time for {key_bits}-bit key: {estimated_time / 3600:.2f} hours")
        return estimated_time
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from PIL import Image
from moviepy.editor import VideoFileClip
from pydub import AudioSegment
import numpy as np
import wave
import base64
import hashlib
import os

# Step 1: Diffie-Hellman Key Exchange Class
class DiffieHellman:
    def __init__(self, prime, generator):
        self.prime = prime
        self.generator = generator
        self.private_key = get_random_bytes(16)  # Generate a random private key
        self.public_key = pow(generator, int.from_bytes(self.private_key, "big"), prime)

    def compute_shared_key(self, other_public_key):
        # Compute the shared key using the other party's public key
        shared_key = pow(other_public_key, int.from_bytes(self.private_key, "big"), self.prime)
        return hashlib.sha256(str(shared_key).encode()).digest()  # SHA-256 for AES key

# Step 2: AES Encryption/Decryption with PBKDF2 for Secure Key Derivation
class AESCipher:
    def __init__(self, key):
        # Using PBKDF2 with a salt and 100,000 iterations
        salt = os.urandom(16)
        self.key = PBKDF2(key, salt, dkLen=32, count=100000)  # Derive a 256-bit AES key
        self.block_size = AES.block_size

    def encrypt(self, data):
        # Encrypt the data using AES in GCM mode
        cipher = AES.new(self.key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(data.encode())
        return base64.b64encode(cipher.nonce + tag + ciphertext).decode()

    def decrypt(self, enc_data):
        # Decrypt the data using AES
        raw_data = base64.b64decode(enc_data)
        nonce, tag, ciphertext = raw_data[:16], raw_data[16:32], raw_data[32:]
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag).decode()

# Step 3A: Steganography for Images
def hide_text_in_image(text, image_path, output_image_path):
    img = Image.open(image_path)
    print(f"Input Image Size: {img.size}")
    img_arr = np.array(img)
    binary_text = ''.join([format(ord(char), '08b') for char in text])
    flat_img = img_arr.flatten()

    for i in range(len(binary_text)):
        flat_img[i] = (flat_img[i] & ~1) | int(binary_text[i])  # Hide data in LSB

    img_arr = flat_img.reshape(img_arr.shape)
    output_img = Image.fromarray(img_arr)
    output_img.save(output_image_path)
    print(f"Steganographic Image Size: {output_img.size}")

def extract_text_from_image(image_path, text_length):
    img = Image.open(image_path)
    img_arr = np.array(img).flatten()
    binary_text = ''.join([str(img_arr[i] & 1) for i in range(text_length * 8)])  # Extract LSB
    text = ''.join([chr(int(binary_text[i:i+8], 2)) for i in range(0, len(binary_text), 8)])
    return text

# Step 3B: Steganography for Video (MP4)
def hide_text_in_video(text, video_path, output_video_path):
    clip = VideoFileClip(video_path)
    print(f"Input Video Duration: {clip.duration} seconds")
    
    # Embed text in the first frame
    binary_text = ''.join([format(ord(char), '08b') for char in text])
    frame = clip.get_frame(0)  # Get the first frame as an array
    flat_frame = frame.flatten()

    for i in range(len(binary_text)):
        flat_frame[i] = (flat_frame[i] & ~1) | int(binary_text[i])

    frame = flat_frame.reshape(frame.shape)
    new_clip = clip.set_duration(clip.duration).set_frame(lambda t: frame if t < 1 else clip.get_frame(t))
    new_clip.write_videofile(output_video_path, codec='libx264')
    print(f"Steganographic Video saved as: {output_video_path}")

def extract_text_from_video(video_path, text_length):
    clip = VideoFileClip(video_path)
    frame = clip.get_frame(0)  # Get the first frame
    flat_frame = frame.flatten()
    binary_text = ''.join([str(flat_frame[i] & 1) for i in range(text_length * 8)])  # Extract LSB
    text = ''.join([chr(int(binary_text[i:i+8], 2)) for i in range(0, len(binary_text), 8)])
    return text

# Step 3C: Steganography for Audio (WAV)
def hide_text_in_audio(text, audio_path, output_audio_path):
    audio = AudioSegment.from_wav(audio_path)
    samples = np.array(audio.get_array_of_samples())
    binary_text = ''.join([format(ord(char), '08b') for char in text])

    for i in range(len(binary_text)):
        samples[i] = (samples[i] & ~1) | int(binary_text[i])  # Modify LSB

    modified_audio = audio._spawn(samples.tobytes())
    modified_audio.export(output_audio_path, format="wav")
    print(f"Steganographic Audio saved as: {output_audio_path}")

def extract_text_from_audio(audio_path, text_length):
    audio = AudioSegment.from_wav(audio_path)
    samples = np.array(audio.get_array_of_samples())
    binary_text = ''.join([str(samples[i] & 1) for i in range(text_length * 8)])  # Extract LSB
    text = ''.join([chr(int(binary_text[i:i+8], 2)) for i in range(0, len(binary_text), 8)])
    return text

# Execution Steps with Verification
def main():
    # Diffie-Hellman Parameters
    prime = 2**127 - 1
    generator = 3

    # Create two users with Diffie-Hellman key exchange
    print("=== Diffie-Hellman Key Exchange ===")
    alice = DiffieHellman(prime, generator)
    bob = DiffieHellman(prime, generator)

    print(f"Alice's Private Key (hex): {alice.private_key.hex()}")
    print(f"Alice's Private Key (normal): {alice.private_key}")
    print(f"Alice's Public Key: {alice.public_key}")
    print(f"Bob's Private Key (hex): {bob.private_key.hex()}")
    print(f"Bob's Private Key (normal): {bob.private_key}")
    print(f"Bob's Public Key: {bob.public_key}")

    # Generate shared AES key using Alice's and Bob's public keys
    shared_key = alice.compute_shared_key(bob.public_key)
    print(f"Shared Key (AES Key, hex): {shared_key.hex()}\n")

        # Simulate cracking time for the shared key
    simulate_crack_time(shared_key)
    # AES encryption using the derived shared key
    print("=== AES Encryption ===")
    aes_cipher = AESCipher(shared_key)
    secret_message = input("Enter the original message to encrypt: ")
    print(f"Original Text: {secret_message}")
    encrypted_message = aes_cipher.encrypt(secret_message)
    print(f"Encrypted Text (Base64): {encrypted_message}\n")

    # Choose media for hiding data
    media_choice = input("Choose media type (image, video, audio): ").strip().lower()
    
    # Define file paths for cover media
    if media_choice == "image":
        image_path = 'luffy_png.png'
        output_image_path = 'stego_image.png'
        # decrypted_image_path = 'decrypted_image.png'
        
        print("=== Steganography Data Hiding in Image ===")
        hide_text_in_image(encrypted_message, image_path, output_image_path)
        print(f"Encrypted message hidden in {output_image_path}.\n")

        # Extract and decrypt the message
        print("=== Decryption Process ===")
        extracted_message = extract_text_from_image(output_image_path, len(encrypted_message))
        print(f"Extracted Encrypted Text from Image: {extracted_message}")
        decrypted_message = aes_cipher.decrypt(extracted_message)
        print(f"Decrypted Text: {decrypted_message}")

	 # # Save the decrypted message as an image
  #       decrypted_img = Image.new('RGB', (100, 100), (255, 255, 255))  # Placeholder for an actual decrypted image
  #       decrypted_img.save(decrypted_image_path)
  #       print(f"Decrypted Image saved as: {decrypted_image_path}")
        
        # Verification
        print("\n=== Verification ===")
        original_img = Image.open(image_path)
        final_img = Image.open(output_image_path)
        print(f"Original Image Size: {original_img.size}")
        print(f"Steganographic Image Size after decryption: {final_img.size}")

    elif media_choice == "video":
        video_path = 'cover_video.mp4'
        output_video_path = 'stego_video.mp4'
        decrypted_video_path = 'decrypted_video.mp4'
        
        print("=== Steganography Data Hiding in Video ===")
        hide_text_in_video(encrypted_message, video_path, output_video_path)
        print(f"Encrypted message hidden in {output_video_path}.\n")

        # Extract and decrypt the message
        print("=== Decryption Process ===")
        extracted_message = extract_text_from_video(output_video_path, len(encrypted_message))
        print(f"Extracted Encrypted Text from Video: {extracted_message}")
        decrypted_message = aes_cipher.decrypt(extracted_message)
        print(f"Decrypted Text: {decrypted_message}")
        print(f"Decrypted Video saved as: {decrypted_video_path}")


        # Verification
        print("\n=== Verification ===")
        original_clip = VideoFileClip(video_path)
        stego_clip = VideoFileClip(output_video_path)
        print(f"Original Video Duration: {original_clip.duration}")
        print(f"Steganographic Video Duration after decryption: {stego_clip.duration}")

    elif media_choice == "audio":
        audio_path = 'cover_audio.wav'
        output_audio_path = 'stego_audio.wav'
        decrypted_audio_path = 'decrypted_audio.wav'
        
        print("=== Steganography Data Hiding in Audio ===")
        hide_text_in_audio(encrypted_message, audio_path, output_audio_path)
        print(f"Encrypted message hidden in {output_audio_path}.\n")

        # Extract and decrypt the message
        print("=== Decryption Process ===")
        extracted_message = extract_text_from_audio(output_audio_path, len(encrypted_message))
        print(f"Extracted Encrypted Text from Audio: {extracted_message}")
        decrypted_message = aes_cipher.decrypt(extracted_message)
        print(f"Decrypted Text: {decrypted_message}")
        print(f"Decrypted Audio saved as: {decrypted_audio_path}")

        # Verification
        print("\n=== Verification ===")
        original_audio = AudioSegment.from_wav(audio_path)
        stego_audio = AudioSegment.from_wav(output_audio_path)
        print(f"Original Audio Length: {len(original_audio)} milliseconds")
        print(f"Steganographic Audio Length after decryption: {len(stego_audio)} milliseconds")

    else:
        print("Invalid media type selected.")
    
    # Final Output Details
    print("\n=== Final Output ===")
    print(f"Alice's Private Key (hex): {alice.private_key.hex()}")
    print(f"Alice's Private Key (normal): {alice.private_key}")
    print(f"Alice's Public Key: {alice.public_key}")
    print(f"Bob's Private Key (hex): {bob.private_key.hex()}")
    print(f"Bob's Private Key (normal): {bob.private_key}")
    print(f"Bob's Public Key: {bob.public_key}")
    print(f"Shared Key (AES Key, hex): {shared_key.hex()}")

    print("Process completed.")
# Run the main function
if __name__ == "__main__":
    main()
