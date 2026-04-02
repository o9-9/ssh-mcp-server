import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import { SSHConnectionManager } from '../build/services/ssh-connection-manager.js';
import { ToolError } from '../build/utils/tool-error.js';

describe('SSH Connection Manager', () => {
  let manager;

  before(() => {
    manager = SSHConnectionManager.getInstance();
  });

  describe('配置管理', () => {
    it('应该正确初始化并设置配置', () => {
      const configs = {
        dev: {
          name: 'dev',
          host: '192.168.1.100',
          port: 22,
          username: 'devuser',
          password: 'devpass'
        }
      };

      manager.setConfig(configs);
      const config = manager.getConfig('dev');
      assert.strictEqual(config.host, '192.168.1.100');
      assert.strictEqual(config.username, 'devuser');
    });

    it('应该能够获取所有服务器信息', () => {
      const configs = {
        dev: {
          name: 'dev',
          host: '192.168.1.100',
          port: 22,
          username: 'devuser',
          password: 'devpass'
        },
        prod: {
          name: 'prod',
          host: '10.0.0.50',
          port: 22,
          username: 'produser',
          password: 'prodpass'
        }
      };

      manager.setConfig(configs);
      const allInfos = manager.getAllServerInfos();

      assert.strictEqual(allInfos.length, 2);
      assert.ok(allInfos.find(c => c.name === 'dev'));
      assert.ok(allInfos.find(c => c.name === 'prod'));
    });

    it('应该能够通过名称获取配置', () => {
      const configs = {
        dev: {
          name: 'dev',
          host: '192.168.1.100',
          port: 22,
          username: 'devuser',
          password: 'devpass'
        }
      };

      manager.setConfig(configs);
      const config = manager.getConfig('dev');

      assert.strictEqual(config.name, 'dev');
      assert.strictEqual(config.host, '192.168.1.100');
    });

    it('获取不存在的配置应抛出错误', () => {
      manager.setConfig({});
      assert.throws(() => {
        manager.getConfig('nonexistent');
      }, /not set/);
    });

    it('无效的命令正则应在配置阶段抛出错误', () => {
      assert.throws(() => {
        manager.setConfig({
          dev: {
            name: 'dev',
            host: '192.168.1.100',
            port: 22,
            username: 'devuser',
            password: 'devpass',
            commandWhitelist: ['[invalid']
          }
        });
      }, /Invalid whitelist pattern/);
    });
  });

  describe('服务器信息', () => {
    it('初始状态应该是未连接', () => {
      const configs = {
        dev: {
          name: 'dev',
          host: '192.168.1.100',
          port: 22,
          username: 'devuser',
          password: 'devpass'
        }
      };

      manager.setConfig(configs);
      const infos = manager.getAllServerInfos();
      const devInfo = infos.find(i => i.name === 'dev');

      assert.ok(devInfo);
      assert.strictEqual(devInfo.connected, false);
    });

    it('服务器信息应包含正确的连接参数', () => {
      const configs = {
        dev: {
          name: 'dev',
          host: '192.168.1.100',
          port: 2222,
          username: 'devuser',
          password: 'devpass'
        }
      };

      manager.setConfig(configs);
      const infos = manager.getAllServerInfos();
      const devInfo = infos.find(i => i.name === 'dev');

      assert.strictEqual(devInfo.host, '192.168.1.100');
      assert.strictEqual(devInfo.port, 2222);
      assert.strictEqual(devInfo.username, 'devuser');
    });

    it('应允许配置的本地路径用于传输', () => {
      const configs = {
        dev: {
          name: 'dev',
          host: '192.168.1.100',
          port: 2222,
          username: 'devuser',
          password: 'devpass',
          allowedLocalPaths: ['/tmp']
        }
      };

      manager.setConfig(configs);

      assert.throws(() => manager['validateLocalPath']('/etc/passwd'), ToolError);
      assert.strictEqual(manager['validateLocalPath']('/tmp/test.txt'), '/tmp/test.txt');
    });
  });

  describe('默认连接名称', () => {
    it('应该使用第一个配置作为默认名称', () => {
      const configs = {
        first: {
          name: 'first',
          host: '1.1.1.1',
          port: 22,
          username: 'user1',
          password: 'pass1'
        },
        second: {
          name: 'second',
          host: '2.2.2.2',
          port: 22,
          username: 'user2',
          password: 'pass2'
        }
      };

      manager.setConfig(configs);
      // 不指定名称时应使用默认名称
      const config = manager.getConfig();
      assert.strictEqual(config.host, '1.1.1.1');
    });

    it('应该支持指定默认连接名称', () => {
      const configs = {
        first: {
          name: 'first',
          host: '1.1.1.1',
          port: 22,
          username: 'user1',
          password: 'pass1'
        },
        second: {
          name: 'second',
          host: '2.2.2.2',
          port: 22,
          username: 'user2',
          password: 'pass2'
        }
      };

      manager.setConfig(configs, 'second');
      const config = manager.getConfig();
      assert.strictEqual(config.host, '2.2.2.2');
    });
  });
});
