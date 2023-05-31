import hmac
import hashlib
import time



def HOTP(key, counter, digits=6):
    # Convert counter to a byte string using big endian encoding
    counter_bytes = counter.to_bytes(8, 'big')

    # Calculate HMAC-SHA1
    hmac_sha1 = hmac.new(key, counter_bytes, hashlib.sha1).digest()

    # Get the last 4 bits of the HMAC-SHA1 value
    offset = hmac_sha1[-1] & 0x0F

    # Extract 4 bytes from the HMAC-SHA1 value
    truncated_hash = hmac_sha1[offset:offset+4]

    # Convert the truncated hash to an integer
    hotp = int.from_bytes(truncated_hash, 'big')

    # Apply a modulo operation to get the desired number of digits
    hotp %= 10 ** digits

    # Convert the HOTP to a zero-padded string
    hotp = str(hotp).zfill(digits)

    return hotp





def generate_HOTP(key, digits=6):
    current_time = int(time.time())
    hotp = HOTP(key, current_time, digits)
    return hotp


def validate_HOTP(key, otp, window_hours=4, digits=6):
    current_time = int(time.time())
    window_seconds = window_hours * 60*60
    for i in range(current_time - window_seconds, current_time + 1):
        generated_code = HOTP(key, i, digits)
        if otp == generated_code:
            return True

    return False


# Example usage
key = b'SecretKey'  # Replace with your secret key

# Generate HOTP
generated_code = generate_HOTP(key)
print(f"Generated HOTP: {generated_code}")

time.sleep(1)
# Simulate receiving OTP
received_otp = generated_code

# received_otp = '014696'


# Validate OTP
is_valid = validate_HOTP(key, received_otp)
if is_valid:
    print("OTP is valid!")
else:
    print("OTP is invalid!")
