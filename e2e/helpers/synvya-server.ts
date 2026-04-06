import { ChildProcessWithoutNullStreams, spawn } from "node:child_process";

const DEFAULT_READY_TIMEOUT_MS = 30_000;
const DEFAULT_SHUTDOWN_TIMEOUT_MS = 10_000;
const DEFAULT_BUNKER_ENV_VAR = "SYNVYA_RESTAURANT_BUNKER_URL";
const DEFAULT_KEYCAST_BASE_URL_ENV_VAR = "KEYCAST_BASE_URL";

export interface StartSynvyaServerOptions {
  cwd: string;
  command: string;
  args?: string[];
  restaurantBunkerUrl: string;
  baseUrl: string;
  healthcheckUrl?: string;
  readyTimeoutMs?: number;
  shutdownTimeoutMs?: number;
  bunkerEnvVar?: string;
  keycastBaseUrl?: string;
  keycastBaseUrlEnvVar?: string;
  env?: Record<string, string | undefined>;
}

export interface StartedSynvyaServer {
  baseUrl: string;
  healthcheckUrl: string;
  restaurantBunkerUrl: string;
  process: ChildProcessWithoutNullStreams;
  output: string[];
  stop(): Promise<void>;
  waitForExit(): Promise<number | null>;
}

function trimTrailingSlash(value: string): string {
  return value.replace(/\/+$/, "");
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitForHealthcheck(
  url: string,
  timeoutMs: number,
  process: ChildProcessWithoutNullStreams,
): Promise<void> {
  const startedAt = Date.now();

  while (Date.now() - startedAt < timeoutMs) {
    if (process.exitCode !== null) {
      throw new Error(
        `Synvya server exited before becoming healthy (exit code ${process.exitCode}).`,
      );
    }

    try {
      const response = await fetch(url);
      if (response.ok) {
        return;
      }
    } catch {
      // Server not ready yet.
    }

    await sleep(250);
  }

  throw new Error(`Synvya server healthcheck did not become ready: ${url}`);
}

async function stopProcess(
  child: ChildProcessWithoutNullStreams,
  timeoutMs: number,
): Promise<void> {
  if (child.exitCode !== null) {
    return;
  }

  child.kill("SIGTERM");

  const exitCode = await Promise.race([
    new Promise<number | null>((resolve) => {
      child.once("exit", (code) => resolve(code));
    }),
    (async () => {
      await sleep(timeoutMs);
      return "timeout" as const;
    })(),
  ]);

  if (exitCode === "timeout" && child.exitCode === null) {
    child.kill("SIGKILL");
    await new Promise<void>((resolve) => {
      child.once("exit", () => resolve());
    });
  }
}

export async function startSynvyaServer(
  options: StartSynvyaServerOptions,
): Promise<StartedSynvyaServer> {
  const healthcheckUrl =
    options.healthcheckUrl ?? `${trimTrailingSlash(options.baseUrl)}/health`;
  const readyTimeoutMs = options.readyTimeoutMs ?? DEFAULT_READY_TIMEOUT_MS;
  const shutdownTimeoutMs =
    options.shutdownTimeoutMs ?? DEFAULT_SHUTDOWN_TIMEOUT_MS;
  const bunkerEnvVar = options.bunkerEnvVar ?? DEFAULT_BUNKER_ENV_VAR;
  const keycastBaseUrlEnvVar =
    options.keycastBaseUrlEnvVar ?? DEFAULT_KEYCAST_BASE_URL_ENV_VAR;

  const child = spawn(options.command, options.args ?? [], {
    cwd: options.cwd,
    env: {
      ...process.env,
      ...options.env,
      [bunkerEnvVar]: options.restaurantBunkerUrl,
      ...(options.keycastBaseUrl
        ? { [keycastBaseUrlEnvVar]: options.keycastBaseUrl }
        : {}),
    },
    stdio: "pipe",
  });

  const output: string[] = [];
  const rememberOutput = (chunk: Buffer) => {
    output.push(chunk.toString("utf8"));
    if (output.length > 200) {
      output.shift();
    }
  };

  child.stdout.on("data", rememberOutput);
  child.stderr.on("data", rememberOutput);

  try {
    await waitForHealthcheck(healthcheckUrl, readyTimeoutMs, child);
  } catch (error) {
    await stopProcess(child, shutdownTimeoutMs);
    const logs = output.join("");
    const suffix = logs ? `\n\nRecent output:\n${logs}` : "";
    throw new Error(
      `${
        error instanceof Error ? error.message : String(error)
      }${suffix}`,
    );
  }

  return {
    baseUrl: trimTrailingSlash(options.baseUrl),
    healthcheckUrl,
    restaurantBunkerUrl: options.restaurantBunkerUrl,
    process: child,
    output,
    async stop() {
      await stopProcess(child, shutdownTimeoutMs);
    },
    waitForExit() {
      return new Promise<number | null>((resolve) => {
        if (child.exitCode !== null) {
          resolve(child.exitCode);
          return;
        }
        child.once("exit", (code) => resolve(code));
      });
    },
  };
}
