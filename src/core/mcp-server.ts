import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { SSHConnectionManager } from "../services/ssh-connection-manager.js";
import { CommandLineParser } from "../cli/command-line-parser.js";
import { Logger } from "../utils/logger.js";
import { registerAllTools } from "../tools/index.js";
import { SERVER_CONFIG } from "../config/server.js";

/**
 * MCP Server class
 */
export class SshMcpServer {
  private server: McpServer;
  private sshManager: SSHConnectionManager;
  private shutdownHandlersRegistered = false;

  constructor() {
    this.server = new McpServer(SERVER_CONFIG);

    this.sshManager = SSHConnectionManager.getInstance();
  }

  /**
   * Register tools
   */
  private registerTools(): void {
    registerAllTools(this.server);
  }

  private registerShutdownHandlers(): void {
    if (this.shutdownHandlersRegistered) {
      return;
    }

    const handleShutdown = (signal: string) => {
      Logger.log(`Received ${signal}, disconnecting SSH clients...`, "info");
      this.sshManager.disconnect();
    };

    process.once("SIGINT", () => handleShutdown("SIGINT"));
    process.once("SIGTERM", () => handleShutdown("SIGTERM"));
    process.once("beforeExit", () => handleShutdown("beforeExit"));

    this.shutdownHandlersRegistered = true;
  }

  /**
   * Run the server
   */
  public async run(): Promise<void> {
    // Initialize SSH configuration
    const parsedArgs = CommandLineParser.parseArgs();
    this.sshManager.setConfig(parsedArgs.configs);
    this.registerShutdownHandlers();

    // Security warning
    const allConfigs = Object.values(parsedArgs.configs);
    if (
      allConfigs.some(
        (c) => !c.commandWhitelist || c.commandWhitelist.length === 0
      )
    ) {
      Logger.log(
        "WARNING: Running without a command whitelist is strongly discouraged. Please configure a whitelist to restrict the commands that can be executed.",
        "info"
      );
    }

    // Pre-connect to all servers if flag is set
    if (parsedArgs.preConnect) {
      Logger.log("Pre-connecting to all configured SSH servers...", "info");
      try {
        await this.sshManager.connectAll();
        Logger.log("Successfully pre-connected to all SSH servers", "info");
      } catch (error) {
        Logger.log(
          `Warning: Some SSH connections failed during pre-connect: ${(error as Error).message}`,
          "error"
        );
      }
    }

    // Register tools
    this.registerTools();

    // Create transport instance and connect
    const transport = new StdioServerTransport();
    await this.server.connect(transport);

    Logger.log("MCP server connection established");
  }
}
