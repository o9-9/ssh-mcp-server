import { Client, ClientChannel } from "ssh2";
import { SocksClient } from "socks";
import {
  SSHConfig,
  SshConnectionConfigMap,
  ServerStatus,
} from "../models/types.js";
import { Logger } from "../utils/logger.js";
import { collectSystemStatus } from "../utils/status-collector.js";
import { ToolError } from "../utils/tool-error.js";
import fs from "fs";
import path from "path";
import { SFTPWrapper } from "ssh2";

/**
 * SSH Connection Manager class
 */
export class SSHConnectionManager {
  private static instance: SSHConnectionManager;
  private clients: Map<string, Client> = new Map();
  private configs: SshConnectionConfigMap = {};
  private connected: Map<string, boolean> = new Map();
  private statusCache: Map<string, ServerStatus> = new Map();
  private pendingConnections: Map<string, Promise<void>> = new Map();
  private pendingStatusCollections: Map<string, NodeJS.Timeout> = new Map();
  private commandWhitelistRegexes: Map<string, RegExp[]> = new Map();
  private commandBlacklistRegexes: Map<string, RegExp[]> = new Map();
  private defaultName: string = "default";

  private constructor() {}

  /**
   * Get singleton instance
   */
  public static getInstance(): SSHConnectionManager {
    if (!SSHConnectionManager.instance) {
      SSHConnectionManager.instance = new SSHConnectionManager();
    }
    return SSHConnectionManager.instance;
  }

  /**
   * Batch set SSH configurations
   */
  public setConfig(
    configs: SshConnectionConfigMap,
    defaultName?: string,
  ): void {
    this.disconnect();

    this.commandWhitelistRegexes.clear();
    this.commandBlacklistRegexes.clear();

    for (const [name, config] of Object.entries(configs)) {
      this.commandWhitelistRegexes.set(
        name,
        this.compilePatterns(config.commandWhitelist, name, "whitelist"),
      );
      this.commandBlacklistRegexes.set(
        name,
        this.compilePatterns(config.commandBlacklist, name, "blacklist"),
      );
    }

    this.configs = configs;
    if (defaultName && configs[defaultName]) {
      this.defaultName = defaultName;
    } else if (Object.keys(configs).length > 0) {
      this.defaultName = Object.keys(configs)[0];
    }
  }

  /**
   * Get specified connection configuration
   */
  public getConfig(name?: string): SSHConfig {
    const key = name || this.defaultName;
    if (!this.configs[key]) {
      throw new Error(`SSH configuration for '${key}' not set`);
    }
    return this.configs[key];
  }

  /**
   * Batch connect all configured SSH connections
   */
  public async connectAll(): Promise<void> {
    const names = Object.keys(this.configs);
    for (const name of names) {
      await this.connect(name);
    }
  }

  /**
   * Connect to SSH with specified name
   */
  public async connect(name?: string): Promise<void> {
    const key = name || this.defaultName;
    if (this.connected.get(key) && this.clients.get(key)) {
      return;
    }
    const existingConnection = this.pendingConnections.get(key);
    if (existingConnection) {
      await existingConnection;
      return;
    }
    const config = this.getConfig(key);
    const client = new Client();
    const connectionPromise = new Promise<void>(async (resolve, reject) => {
      client.on("ready", () => {
        this.connected.set(key, true);
        Logger.log(
          `Successfully connected to SSH server [${key}] ${config.host}:${config.port}`,
        );

        // 先 resolve，让用户命令可以立即执行
        resolve();

        // 延迟执行系统状态收集，避免与用户的第一个命令竞争 SSH 通道
        const existingStatusCollection = this.pendingStatusCollections.get(key);
        if (existingStatusCollection) {
          clearTimeout(existingStatusCollection);
        }

        const timeoutId = setTimeout(() => {
          this.pendingStatusCollections.delete(key);
          collectSystemStatus(client, key)
            .then((status) => {
              this.statusCache.set(key, status);
              Logger.log(`System status collected for [${key}]`, "info");
            })
            .catch((error) => {
              Logger.log(
                `Failed to collect system status for [${key}]: ${(error as Error).message}`,
                "error",
              );
              // Set basic status even if collection fails
              this.statusCache.set(key, {
                reachable: true,
                lastUpdated: new Date().toISOString(),
              });
            });
        }, 1000); // 延迟 1 秒，确保用户命令有足够的时间窗口

        this.pendingStatusCollections.set(key, timeoutId);
      });
      client.on("error", (err: Error) => {
        this.connected.set(key, false);
        reject(
          new ToolError(
            "SSH_CONNECTION_FAILED",
            `SSH connection [${key}] failed: ${err.message}`,
            true,
          ),
        );
      });
      client.on("close", () => {
        this.connected.set(key, false);
        this.clients.delete(key);
        this.pendingConnections.delete(key);
        Logger.log(`SSH connection [${key}] closed`, "info");
      });
      const sshConfig: any = {
        host: config.host,
        port: config.port,
        username: config.username,
      };
      // Add SOCKS proxy configuration if provided
      if (config.socksProxy) {
        try {
          // Parse SOCKS proxy URL
          const proxyUrl = new URL(config.socksProxy);
          const proxyHost = proxyUrl.hostname;
          const proxyPort = parseInt(proxyUrl.port, 10);

          Logger.log(
            `Using SOCKS proxy for [${key}]: ${config.socksProxy}`,
            "info",
          );

          // Create SOCKS connection
          const { socket } = await SocksClient.createConnection({
            proxy: {
              host: proxyHost,
              port: proxyPort,
              type: 5,
            },
            command: "connect",
            destination: {
              host: config.host,
              port: config.port,
            },
          });

          // Set the socket as the sock for SSH connection
          sshConfig.sock = socket;
          Logger.log(
            `SSH config object with SOCKS proxy: ${JSON.stringify(
              sshConfig,
              (k, v) => (k === "sock" ? "[Socket object]" : v),
            )}`,
            "info",
          );
        } catch (err) {
          return reject(
            new ToolError(
              "SSH_CONNECTION_FAILED",
              `Failed to create SOCKS proxy connection for [${key}]: ${
                (err as Error).message
              }`,
              true,
            ),
          );
        }
      }
      if (config.agent) {
        sshConfig.agent = config.agent;
        Logger.log(`Using SSH agent authentication for [${key}]: ${config.agent}`, "info");
      } else if (config.privateKey) {
        try {
          sshConfig.privateKey = fs.readFileSync(config.privateKey, "utf8");
          if (config.passphrase) {
            sshConfig.passphrase = config.passphrase;
          }
          Logger.log(
            `Using SSH private key authentication for [${key}]`,
            "info",
          );
        } catch (err) {
          return reject(
            new ToolError(
              "LOCAL_FILE_READ_FAILED",
              `Failed to read private key file for [${key}]: ${
                (err as Error).message
              }`,
              false,
            ),
          );
        }
      } else if (config.password) {
        sshConfig.password = config.password;
        Logger.log(`Using password authentication for [${key}]`, "info");
      } else {
        return reject(
          new ToolError(
            "SSH_AUTHENTICATION_MISSING",
            `No valid authentication method provided for [${key}] (agent, password or private key)`,
            false,
          ),
        );
      }
      client.connect(sshConfig);
    });
    this.pendingConnections.set(key, connectionPromise);

    try {
      await connectionPromise;
      this.clients.set(key, client);
    } finally {
      this.pendingConnections.delete(key);
    }
  }

  /**
   * Get SSH Client with specified name
   */
  public getClient(name?: string): Client {
    const key = name || this.defaultName;
    const client = this.clients.get(key);
    if (!client) {
      throw new Error(`SSH client for '${key}' not connected`);
    }
    return client;
  }

  /**
   * Ensure SSH client is connected
   * @private
   */
  private async ensureConnected(name?: string): Promise<Client> {
    const key = name || this.defaultName;
    if (!this.connected.get(key) || !this.clients.get(key)) {
      await this.connect(key);
    }
    const client = this.clients.get(key);
    if (!client) {
      throw new Error(`SSH client for '${key}' not initialized`);
    }
    return client;
  }

  private compilePatterns(
    patterns: string[] | undefined,
    connectionName: string,
    kind: "whitelist" | "blacklist",
  ): RegExp[] {
    if (!patterns || patterns.length === 0) {
      return [];
    }

    return patterns.map((pattern) => {
      try {
        return new RegExp(pattern);
      } catch (error) {
        throw new Error(
          `Invalid ${kind} pattern for '${connectionName}': ${pattern} (${(error as Error).message})`,
        );
      }
    });
  }

  private validateCommand(
    command: string,
    name?: string,
  ): { isAllowed: boolean; reason?: string } {
    const key = name || this.defaultName;
    // Check whitelist (if whitelist is configured, command must match one of the patterns to be allowed)
    const whitelistRegexes = this.commandWhitelistRegexes.get(key) || [];
    if (whitelistRegexes.length > 0) {
      const matchesWhitelist = whitelistRegexes.some((regex) =>
        regex.test(command),
      );
      if (!matchesWhitelist) {
        return {
          isAllowed: false,
          reason: "Command not in whitelist, execution forbidden",
        };
      }
    }
    // Check blacklist (if command matches any pattern in blacklist, execution is forbidden)
    const blacklistRegexes = this.commandBlacklistRegexes.get(key) || [];
    if (blacklistRegexes.length > 0) {
      const matchesBlacklist = blacklistRegexes.some((regex) =>
        regex.test(command),
      );
      if (matchesBlacklist) {
        return {
          isAllowed: false,
          reason: "Command matches blacklist, execution forbidden",
        };
      }
    }
    // Validation passed
    return {
      isAllowed: true,
    };
  }

  private formatCommandFailure(
    stdout: string,
    stderr: string,
    exitCode?: number,
    exitSignal?: string,
  ): string {
    const outputSections: string[] = [];

    if (stdout) {
      outputSections.push(stdout);
    }

    if (stderr) {
      outputSections.push(`[stderr]\n${stderr}`);
    }

    if (exitCode !== undefined) {
      outputSections.push(`[exit code] ${exitCode}`);
    }

    if (exitSignal) {
      outputSections.push(`[signal] ${exitSignal}`);
    }

    return outputSections.join("\n");
  }

  /**
   * Execute SSH command
   */
  public async executeCommand(
    cmdString: string,
    directory?: string,
    name?: string,
    options: { timeout?: number } = {},
  ): Promise<string> {
    // Validate command input and security
    const validationResult = this.validateCommand(cmdString, name);
    if (!validationResult.isAllowed) {
      throw new ToolError(
        "COMMAND_VALIDATION_FAILED",
        `Command validation failed: ${validationResult.reason}`,
        false,
      );
    }

    // Ensure SSH connection is established
    const client = await this.ensureConnected(name);

    // Get configuration to check PTY setting
    const config = this.getConfig(name);

    const commandToRun = directory
      ? `cd -- ${JSON.stringify(directory)} && ${cmdString}`
      : cmdString;

    // Configure execution options with defaults
    const timeout = options.timeout || 30000; // Default 30 seconds timeout

    return new Promise<string>((resolve, reject) => {
      let timeoutId: NodeJS.Timeout;
      let settled = false;

      // Cleanup function to clear timeout and prevent memory leaks
      const cleanup = () => {
        if (timeoutId) {
          clearTimeout(timeoutId);
        }
      };

      // Execute command via SSH exec
      client.exec(
        commandToRun,
        // allocate a pseudo-tty (default: true)
        { pty: config.pty !== undefined ? config.pty : true },
        (err: Error | undefined, stream: ClientChannel) => {
          // Handle immediate execution errors
          if (err) {
            cleanup();
            reject(
              new ToolError(
                "COMMAND_EXECUTION_ERROR",
                `Command execution error: ${err.message}`,
                true,
              ),
            );
            return;
          }

          // Initialize data buffers for stdout and stderr
          let data = "";
          let errorData = "";
          let exitCode: number | undefined;
          let exitSignal: string | undefined;

          // Set up event listeners for command output streams
          stream.on("data", (chunk: Buffer) => (data += chunk.toString())); // Collect stdout data
          stream.stderr.on(
            "data",
            (chunk: Buffer) => (errorData += chunk.toString()), // Collect stderr data
          );

          stream.on(
            "exit",
            (code: number | undefined, signal: string | undefined) => {
              exitCode = code;
              exitSignal = signal;
            },
          );

          // Handle command completion and exit code
          stream.on("close", (code?: number, signal?: string) => {
            cleanup();
            if (settled) {
              return;
            }
            settled = true;

            if (exitCode === undefined) {
              exitCode = code;
            }

            if (!exitSignal && signal) {
              exitSignal = signal;
            }

            const stdout = data.trimEnd();
            const stderr = errorData.trimEnd();
            const hasNonZeroExitCode =
              exitCode !== undefined && exitCode !== 0;
            const hasExitSignal =
              exitSignal !== undefined && exitSignal !== "";

            if (hasNonZeroExitCode || hasExitSignal) {
              reject(
                new ToolError(
                  "COMMAND_EXECUTION_ERROR",
                  this.formatCommandFailure(
                    stdout,
                    stderr,
                    exitCode,
                    exitSignal,
                  ) ||
                    (hasExitSignal
                      ? `Command terminated by signal ${exitSignal}${
                          exitCode !== undefined ? ` (exit code ${exitCode})` : ""
                        }`
                      : `Command failed with exit code ${exitCode}`),
                  false,
                ),
              );
              return;
            }

            resolve(stdout);
          });

          // Handle stream errors during execution
          stream.on("error", (err: Error) => {
            cleanup();
            settled = true;
            reject(
              new ToolError(
                "COMMAND_EXECUTION_ERROR",
                `Stream error: ${err.message}`,
                true,
              ),
            );
          });

          // Set timeout for command execution
          timeoutId = setTimeout(() => {
            try {
              // Try to gracefully close the stream first
              stream.close();
            } catch (e) {
              // Ignore errors when closing streams during timeout
            }

            if (!settled) {
              settled = true;
              const stdout = data.trimEnd();
              const stderr = errorData.trimEnd();
              reject(
                new ToolError(
                  "COMMAND_TIMEOUT",
                  [
                    this.formatCommandFailure(stdout, stderr),
                    `[timeout] Command timed out after ${timeout}ms`,
                  ]
                    .filter(Boolean)
                    .join("\n"),
                  true,
                ),
              );
            }
          }, timeout);
        },
      );
    });
  }

  /**
   * Upload file
   */
  private validateLocalPath(localPath: string): string {
    const resolvedPath = path.resolve(localPath);
    const allowedRoots = new Set<string>([process.cwd()]);

    for (const config of Object.values(this.configs)) {
      for (const allowedPath of config.allowedLocalPaths || []) {
        allowedRoots.add(path.resolve(allowedPath));
      }
    }

    const isAllowed = Array.from(allowedRoots).some(
      (allowedRoot) =>
        resolvedPath === allowedRoot ||
        resolvedPath.startsWith(`${allowedRoot}${path.sep}`),
    );

    if (!isAllowed) {
      throw new ToolError(
        "LOCAL_PATH_NOT_ALLOWED",
        "Path traversal detected. Local path must be within the working directory or configured allowed local paths.",
        false,
      );
    }
    return resolvedPath;
  }

  /**
   * Upload file
   */
  public async upload(
    localPath: string,
    remotePath: string,
    name?: string,
  ): Promise<string> {
    const validatedLocalPath = this.validateLocalPath(localPath);
    const client = await this.ensureConnected(name);

    return new Promise<string>((resolve, reject) => {
      client.sftp((err: Error | undefined, sftp: SFTPWrapper) => {
        if (err) {
          return reject(
            new ToolError(
              "SFTP_ERROR",
              `SFTP connection failed: ${err.message}`,
              true,
            ),
          );
        }

        const readStream = fs.createReadStream(validatedLocalPath);
        const writeStream = sftp.createWriteStream(remotePath);

        const cleanup = () => {
          sftp.end();
        };

        writeStream.on("close", () => {
          cleanup();
          resolve("File uploaded successfully");
        });

        writeStream.on("error", (err: Error) => {
          cleanup();
          reject(
            new ToolError("SFTP_ERROR", `File upload failed: ${err.message}`, true),
          );
        });

        readStream.on("error", (err: Error) => {
          cleanup();
          reject(
            new ToolError(
              "LOCAL_FILE_READ_FAILED",
              `Failed to read local file: ${err.message}`,
              false,
            ),
          );
        });

        readStream.pipe(writeStream);
      });
    });
  }

  /**
   * Download file
   */
  public async download(
    remotePath: string,
    localPath: string,
    name?: string,
  ): Promise<string> {
    const validatedLocalPath = this.validateLocalPath(localPath);
    const client = await this.ensureConnected(name);

    return new Promise<string>((resolve, reject) => {
      client.sftp((err: Error | undefined, sftp: SFTPWrapper) => {
        if (err) {
          return reject(
            new ToolError(
              "SFTP_ERROR",
              `SFTP connection failed: ${err.message}`,
              true,
            ),
          );
        }

        const readStream = sftp.createReadStream(remotePath);
        const writeStream = fs.createWriteStream(validatedLocalPath);

        const cleanup = () => {
          sftp.end();
        };

        writeStream.on("finish", () => {
          cleanup();
          resolve("File downloaded successfully");
        });

        writeStream.on("error", (err: Error) => {
          cleanup();
          reject(
            new ToolError(
              "LOCAL_FILE_WRITE_FAILED",
              `Failed to save file: ${err.message}`,
              false,
            ),
          );
        });

        readStream.on("error", (err: Error) => {
          cleanup();
          reject(
            new ToolError(
              "SFTP_ERROR",
              `File download failed: ${err.message}`,
              true,
            ),
          );
        });

        readStream.pipe(writeStream);
      });
    });
  }

  /**
   * Disconnect SSH connection
   */
  public disconnect(): void {
    for (const timeoutId of this.pendingStatusCollections.values()) {
      clearTimeout(timeoutId);
    }
    this.pendingStatusCollections.clear();

    if (this.clients.size > 0) {
      for (const client of this.clients.values()) {
        client.end();
      }
      this.clients.clear();
    }

    this.connected.clear();
    this.statusCache.clear();
    this.pendingConnections.clear();
    this.commandWhitelistRegexes.clear();
    this.commandBlacklistRegexes.clear();
  }

  /**
   * Get basic information of all configured servers
   */
  public getAllServerInfos(): Array<{
    name: string;
    host: string;
    port: number;
    username: string;
    connected: boolean;
    status?: ServerStatus;
  }> {
    return Object.keys(this.configs).map((key) => {
      const config = this.configs[key];
      const status = this.statusCache.get(key);
      return {
        name: key,
        host: config.host,
        port: config.port,
        username: config.username,
        connected: this.connected.get(key) === true,
        status: status,
      };
    });
  }
}
