import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { readFile } from 'fs/promises';

vi.mock('fs/promises', () => ({
  readFile: vi.fn(),
}));

const mockFetch = vi.fn();
global.fetch = mockFetch as unknown as typeof fetch;

const mockedReadFile = readFile as unknown as ReturnType<typeof vi.fn>;

describe('jar-tools MCP server', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    delete process.env.JARTOOLS_LICENSE_KEY;
    mockedReadFile.mockResolvedValue(Buffer.from('fake jar bytes'));
  });

  afterEach(() => {
    delete process.env.JARTOOLS_LICENSE_KEY;
  });

  describe('scanJarSecurity', () => {
    it('rejects unsupported file extensions before touching the network', async () => {
      const { scanJarSecurity } = await import('./index.js');
      await expect(scanJarSecurity('/path/to/notes.txt')).rejects.toThrow(
        'Only .jar, .zip, or .class files are supported.'
      );
      expect(mockFetch).not.toHaveBeenCalled();
    });

    it('posts to jar-report for .jar files and returns the parsed result', async () => {
      const { scanJarSecurity } = await import('./index.js');
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () =>
          Promise.resolve({
            success: true,
            redacted: true,
            data: { risk_level: 'Low', class_count: 10, suspicious_class_count: 0 },
          }),
      });

      const result = await scanJarSecurity('/path/to/app.jar');

      expect(mockFetch).toHaveBeenCalledWith(
        'https://jar.tools/api/v1/security-scan/jar-report',
        expect.objectContaining({ method: 'POST' })
      );
      expect(result.data?.risk_level).toBe('Low');
      expect(result.redacted).toBe(true);
    });

    it('posts to class-report for .class files', async () => {
      const { scanJarSecurity } = await import('./index.js');
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve({ success: true, data: { risk_level: 'Medium' } }),
      });

      await scanJarSecurity('/path/to/Foo.class');

      expect(mockFetch).toHaveBeenCalledWith(
        'https://jar.tools/api/v1/security-scan/class-report',
        expect.anything()
      );
    });

    it('sends X-License-Key when a license key is provided as an argument', async () => {
      const { scanJarSecurity } = await import('./index.js');
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve({ success: true, data: { risk_level: 'Low' } }),
      });

      await scanJarSecurity('/path/to/app.jar', 'PRO-KEY-123');

      const [, options] = mockFetch.mock.calls[0];
      expect(options.headers['X-License-Key']).toBe('PRO-KEY-123');
    });

    it('falls back to the JARTOOLS_LICENSE_KEY environment variable', async () => {
      process.env.JARTOOLS_LICENSE_KEY = 'ENV-KEY-456';
      const { scanJarSecurity } = await import('./index.js');
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve({ success: true, data: { risk_level: 'Low' } }),
      });

      await scanJarSecurity('/path/to/app.jar');

      const [, options] = mockFetch.mock.calls[0];
      expect(options.headers['X-License-Key']).toBe('ENV-KEY-456');
    });

    it('throws a helpful message on a 429 rate-limit response', async () => {
      const { scanJarSecurity } = await import('./index.js');
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 429,
        json: () =>
          Promise.resolve({
            error: 'rate_limit_reached',
            message: 'Hourly free security scan limit reached.',
            reset: '2026-07-20T16:00:00Z',
            upgradeUrl: 'https://jar.tools/pro',
          }),
      });

      await expect(scanJarSecurity('/path/to/app.jar')).rejects.toThrow(
        /Hourly free security scan limit reached.*Resets at 2026-07-20T16:00:00Z.*Upgrade: https:\/\/jar\.tools\/pro/s
      );
    });

    it('throws the server error message on a non-OK, non-429 response', async () => {
      const { scanJarSecurity } = await import('./index.js');
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 413,
        json: () =>
          Promise.resolve({ success: false, error: 'File is too large for the current scanner limit.' }),
      });

      await expect(scanJarSecurity('/path/to/app.jar')).rejects.toThrow(
        'File is too large for the current scanner limit.'
      );
    });
  });
});
