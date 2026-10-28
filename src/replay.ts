/** Remembers delivery ids for a while so the same webhook can't be processed twice. In-memory; use Redis for clusters. */
export class ReplayGuard {
  private seenUntil = new Map<string, number>();

  constructor(private readonly ttlSeconds = 600, private readonly maxEntries = 100_000) {}

  /** Returns true if `id` was already seen (a replay); otherwise records it and returns false. */
  check(id: string, now = Date.now() / 1000): boolean {
    for (const [k, until] of this.seenUntil) {
      if (until > now) break; // Map keeps insertion order, so the oldest entries come first
      this.seenUntil.delete(k);
    }
    const until = this.seenUntil.get(id);
    if (until !== undefined && until > now) return true;
    if (this.seenUntil.size >= this.maxEntries) this.seenUntil.delete(this.seenUntil.keys().next().value as string);
    this.seenUntil.set(id, now + this.ttlSeconds);
    return false;
  }

  get size(): number {
    return this.seenUntil.size;
  }
}
