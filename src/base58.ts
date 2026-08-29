/** Base58btc encoding used by did:key multibase identifiers. */

const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

const INDEX: Record<string, number> = {};
for (let i = 0; i < ALPHABET.length; i++) {
  INDEX[ALPHABET[i] as string] = i;
}

/** Encode bytes with the base58btc alphabet, preserving leading zeroes. */
export function base58Encode(data: Uint8Array): string {
  let zeroes = 0;
  while (zeroes < data.length && data[zeroes] === 0) zeroes++;

  const encoded: number[] = [];
  for (let i = zeroes; i < data.length; i++) {
    let carry = data[i] as number;
    for (let j = 0; j < encoded.length; j++) {
      carry += (encoded[j] as number) * 256;
      encoded[j] = carry % 58;
      carry = Math.floor(carry / 58);
    }
    while (carry > 0) {
      encoded.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }

  let result = "1".repeat(zeroes);
  for (let i = encoded.length - 1; i >= 0; i--) {
    result += ALPHABET[encoded[i] as number];
  }
  return result;
}

/** Decode a base58btc string into bytes, rejecting invalid characters. */
export function base58Decode(value: string): Uint8Array {
  let zeroes = 0;
  while (zeroes < value.length && value[zeroes] === "1") zeroes++;

  const decoded: number[] = [];
  for (let i = zeroes; i < value.length; i++) {
    const digit = INDEX[value[i] as string];
    if (digit === undefined) {
      throw new Error(`invalid base58btc character: ${value[i]}`);
    }
    let carry = digit;
    for (let j = 0; j < decoded.length; j++) {
      carry += (decoded[j] as number) * 58;
      decoded[j] = carry % 256;
      carry = Math.floor(carry / 256);
    }
    while (carry > 0) {
      decoded.push(carry % 256);
      carry = Math.floor(carry / 256);
    }
  }

  const result = new Uint8Array(zeroes + decoded.length);
  for (let i = 0; i < decoded.length; i++) {
    result[zeroes + i] = decoded[decoded.length - 1 - i] as number;
  }
  return result;
}
