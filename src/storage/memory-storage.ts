export interface Storage {
  read(): Promise<string | null>;
  write(data: string): Promise<void>;
}

export class MemoryStorage implements Storage {
  private data: string | null = null;

  async read(): Promise<string | null> {
    return this.data;
  }

  async write(data: string): Promise<void> {
    this.data = data;
  }
}
