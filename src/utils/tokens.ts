let encoder: { encode: (text: string) => ArrayLike<number> } | null = null;

export async function initTokenizer(): Promise<void> {
  try {
    const { encoding_for_model } = await import("tiktoken");
    encoder = encoding_for_model("gpt-4o");
  } catch {
    encoder = null;
  }
}

export function countTokens(text: string): number {
  if (!encoder) {
    return Math.ceil(text.length / 4);
  }
  return encoder.encode(text).length;
}
