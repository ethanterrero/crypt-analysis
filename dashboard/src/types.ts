export type CipherOption = 'aes256' | 'chacha20';

export interface TestResult {
  cipher: string;
  file_name: string;
  file_size_bytes: number;
  ciphertext_size_bytes: number;

  integrity: {
    passed: boolean;
    encrypt_success: boolean;
    decrypt_success: boolean;
    roundtrip_match: boolean;
  };

  performance: {
    encrypt_seconds: number;
    encrypt_mb_per_second: number;
    encrypt_cycles: number;
    encrypt_cycles_per_byte: number;
    decrypt_seconds: number;
    decrypt_mb_per_second: number;
    decrypt_cycles: number;
    decrypt_cycles_per_byte: number;
  };

  entropy: {
    available: boolean;
    entropy_bits_per_byte: number;
    min_byte_freq: number;
    max_byte_freq: number;
    total_bytes: number;
    passed: boolean;
  };

  frequency: {
    available: boolean;
    chi_squared: number;
    p_value: number;
    degrees_of_freedom: number;
    total_bytes: number;
    passed: boolean;
  };

  avalanche: {
    applicable: boolean;
    available: boolean;
    avg_bit_change_pct: number;
    min_bit_change_pct: number;
    max_bit_change_pct: number;
    std_dev: number;
    bits_tested: number;
    ciphertext_bits: number;
    note: string;
    passed: boolean;
  };
}
