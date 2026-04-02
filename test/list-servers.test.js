import { describe, it } from 'node:test';
import assert from 'node:assert';
import { formatServerList } from '../build/tools/list-servers.js';

describe('List Servers Tool', () => {
  it('没有配置时应返回友好提示', () => {
    assert.strictEqual(formatServerList([]), 'No SSH servers configured.');
  });

  it('应返回可读摘要和原始 JSON', () => {
    const output = formatServerList([
      {
        name: 'dev',
        host: '192.168.1.100',
        port: 22,
        username: 'root',
        connected: true,
        status: {
          reachable: true,
          hostname: 'dev-box',
          osName: 'Linux',
          lastUpdated: '2026-04-02T12:00:00.000Z'
        }
      }
    ]);

    assert.match(output, /Configured SSH servers:/);
    assert.match(output, /\[connected\] dev \| root@192.168.1.100:22/);
    assert.match(output, /hostname=dev-box/);
    assert.match(output, /Raw JSON:/);
    assert.match(output, /"name": "dev"/);
  });
});
