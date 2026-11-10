using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Text.Json;

namespace Lantern.App.Services;

public sealed record DeviceAutomationRequest(
    int ProtocolVersion,
    string? Command,
    string? AutomationId,
    bool? Paused);

public sealed record DeviceAutomationResponse(
    bool Success,
    string? Error,
    string? DeviceName,
    bool? Paused)
{
    public static DeviceAutomationResponse Failed(string error) =>
        new(false, error, null, null);
}

public sealed class DeviceAutomationPipeServer : IAsyncDisposable
{
    public const string PipeName = "LANternControl.DeviceAutomation.v1";

    private const int MaximumRequestBytes = 4096;
    private static readonly TimeSpan RequestReadTimeout = TimeSpan.FromSeconds(5);
    private static readonly JsonSerializerOptions SerializerOptions =
        new(JsonSerializerDefaults.Web);

    private readonly Func<DeviceAutomationRequest, Task<DeviceAutomationResponse>> handler;
    private readonly string pipeName;
    private readonly CancellationTokenSource lifetime = new();
    private Task? listenerTask;
    private int started;
    private int disposed;

    public DeviceAutomationPipeServer(
        Func<DeviceAutomationRequest, Task<DeviceAutomationResponse>> handler,
        string pipeName = PipeName)
    {
        ArgumentNullException.ThrowIfNull(handler);
        ArgumentException.ThrowIfNullOrWhiteSpace(pipeName);
        this.handler = handler;
        this.pipeName = pipeName;
    }

    public void Start()
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        if (Interlocked.CompareExchange(ref started, 1, 0) == 0)
        {
            listenerTask = Task.Run(() => ListenAsync(lifetime.Token));
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0)
        {
            return;
        }

        lifetime.Cancel();
        if (listenerTask is not null)
        {
            await listenerTask.ConfigureAwait(false);
        }

        lifetime.Dispose();
    }

    private async Task ListenAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                using var server = new NamedPipeServerStream(
                    pipeName,
                    PipeDirection.InOut,
                    maxNumberOfServerInstances: 1,
                    PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly,
                    inBufferSize: 4096,
                    outBufferSize: 4096);

                await server.WaitForConnectionAsync(cancellationToken).ConfigureAwait(false);

                string? requestLine;
                using (var readTimeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
                {
                    readTimeout.CancelAfter(RequestReadTimeout);
                    requestLine = await ReadLineAsync(server, readTimeout.Token).ConfigureAwait(false);
                }

                if (requestLine is null)
                {
                    continue;
                }

                var response = await DispatchAsync(requestLine).ConfigureAwait(false);
                await WriteResponseAsync(server, response, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                break;
            }
            catch (OperationCanceledException)
            {
                // A client that connects but does not finish its request is discarded.
            }
            catch (Exception exception) when (
                exception is IOException or UnauthorizedAccessException or InvalidDataException)
            {
                // A pipe may already be owned by another LANtern instance. Retry without
                // affecting the UI or interrupting the main application.
                try
                {
                    await Task.Delay(TimeSpan.FromMilliseconds(250), cancellationToken)
                        .ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    break;
                }
            }
        }
    }

    private async Task<DeviceAutomationResponse> DispatchAsync(string requestJson)
    {
        DeviceAutomationRequest? request;
        try
        {
            request = JsonSerializer.Deserialize<DeviceAutomationRequest>(
                requestJson,
                SerializerOptions);
        }
        catch (JsonException)
        {
            return DeviceAutomationResponse.Failed("The automation request is not valid JSON.");
        }

        if (request is null)
        {
            return DeviceAutomationResponse.Failed("The automation request is empty.");
        }

        if (request.ProtocolVersion != 1)
        {
            return DeviceAutomationResponse.Failed(
                $"Unsupported automation protocol version: {request.ProtocolVersion}.");
        }

        if (!string.Equals(request.Command, "SetPaused", StringComparison.Ordinal))
        {
            return DeviceAutomationResponse.Failed("Unsupported automation command.");
        }

        if (!IsValidPauseAutomationId(request.AutomationId))
        {
            return DeviceAutomationResponse.Failed("The device pause identifier is invalid.");
        }

        if (!request.Paused.HasValue)
        {
            return DeviceAutomationResponse.Failed("The requested pause state is missing.");
        }

        try
        {
            return await handler(request).ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            var message = exception.Message.Trim();
            if (message.Length > 512)
            {
                message = message[..512];
            }

            return DeviceAutomationResponse.Failed(
                string.IsNullOrWhiteSpace(message)
                    ? "LANtern could not apply the requested device rule."
                    : message);
        }
    }

    private static bool IsValidPauseAutomationId(string? automationId)
    {
        const string prefix = "pause_";
        if (automationId is null ||
            !automationId.StartsWith(prefix, StringComparison.Ordinal) ||
            automationId.Length != prefix.Length + 12)
        {
            return false;
        }

        return automationId.AsSpan(prefix.Length).IndexOfAnyExcept("0123456789ABCDEFabcdef") < 0;
    }

    private static async Task<string?> ReadLineAsync(
        Stream stream,
        CancellationToken cancellationToken)
    {
        using var request = new MemoryStream();
        var buffer = new byte[512];

        while (true)
        {
            var bytesRead = await stream.ReadAsync(buffer.AsMemory(), cancellationToken)
                .ConfigureAwait(false);
            if (bytesRead == 0)
            {
                if (request.Length == 0)
                {
                    return null;
                }

                throw new InvalidDataException(
                    "The automation request ended before its newline terminator.");
            }

            for (var index = 0; index < bytesRead; index++)
            {
                if (buffer[index] == (byte)'\n')
                {
                    return Encoding.UTF8.GetString(request.GetBuffer(), 0, (int)request.Length)
                        .TrimEnd('\r');
                }

                request.WriteByte(buffer[index]);
                if (request.Length > MaximumRequestBytes)
                {
                    throw new InvalidDataException(
                        $"The automation request exceeds {MaximumRequestBytes} bytes.");
                }
            }
        }
    }

    private static async Task WriteResponseAsync(
        Stream stream,
        DeviceAutomationResponse response,
        CancellationToken cancellationToken)
    {
        var json = JsonSerializer.SerializeToUtf8Bytes(response, SerializerOptions);
        await stream.WriteAsync(json, cancellationToken).ConfigureAwait(false);
        await stream.WriteAsync(new byte[] { (byte)'\n' }, cancellationToken)
            .ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }
}
