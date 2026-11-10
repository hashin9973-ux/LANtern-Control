using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using Lantern.App.Services;
using Xunit;

namespace Lantern.App.Tests;

public sealed class DeviceAutomationPipeServerTests
{
    [Fact]
    public async Task SetPausedRequest_InvokesHandlerAndReturnsItsResult()
    {
        var pipeName = $"LANternControl.Tests.{Guid.NewGuid():N}";
        DeviceAutomationRequest? received = null;
        await using var server = new DeviceAutomationPipeServer(
            request =>
            {
                received = request;
                return Task.FromResult(
                    new DeviceAutomationResponse(true, null, "Test phone", request.Paused));
            },
            pipeName);

        server.Start();
        var response = await SendRequestAsync(
            pipeName,
            new DeviceAutomationRequest(1, "SetPaused", "pause_AABBCCDDEEFF", true));

        Assert.NotNull(received);
        Assert.Equal("pause_AABBCCDDEEFF", received.AutomationId);
        Assert.True(received.Paused);
        Assert.True(response.Success);
        Assert.Equal("Test phone", response.DeviceName);
        Assert.True(response.Paused);
    }

    [Fact]
    public async Task InvalidAutomationId_IsRejectedBeforeCallingHandler()
    {
        var pipeName = $"LANternControl.Tests.{Guid.NewGuid():N}";
        var handlerCalled = false;
        await using var server = new DeviceAutomationPipeServer(
            _ =>
            {
                handlerCalled = true;
                return Task.FromResult(new DeviceAutomationResponse(true, null, "Unexpected", true));
            },
            pipeName);

        server.Start();
        var response = await SendRequestAsync(
            pipeName,
            new DeviceAutomationRequest(1, "SetPaused", "pause_not-a-mac", true));

        Assert.False(handlerCalled);
        Assert.False(response.Success);
        Assert.Contains("identifier is invalid", response.Error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task UnsupportedProtocolVersion_IsRejected()
    {
        var pipeName = $"LANternControl.Tests.{Guid.NewGuid():N}";
        await using var server = new DeviceAutomationPipeServer(
            _ => Task.FromResult(new DeviceAutomationResponse(true, null, "Unexpected", true)),
            pipeName);

        server.Start();
        var response = await SendRequestAsync(
            pipeName,
            new DeviceAutomationRequest(2, "SetPaused", "pause_AABBCCDDEEFF", true));

        Assert.False(response.Success);
        Assert.Contains("protocol version", response.Error, StringComparison.OrdinalIgnoreCase);
    }

    private static async Task<DeviceAutomationResponse> SendRequestAsync(
        string pipeName,
        DeviceAutomationRequest request)
    {
        using var client = new NamedPipeClientStream(
            ".",
            pipeName,
            PipeDirection.InOut,
            PipeOptions.Asynchronous);
        await client.ConnectAsync(5000);

        var encoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);
        using var writer = new StreamWriter(client, encoding, 1024, leaveOpen: true)
        {
            AutoFlush = true,
        };
        using var reader = new StreamReader(client, encoding, detectEncodingFromByteOrderMarks: false, 1024, leaveOpen: true);

        await writer.WriteLineAsync(JsonSerializer.Serialize(request, new JsonSerializerOptions(JsonSerializerDefaults.Web)));
        var responseJson = await reader.ReadLineAsync();
        Assert.False(string.IsNullOrWhiteSpace(responseJson));

        return JsonSerializer.Deserialize<DeviceAutomationResponse>(
            responseJson!,
            new JsonSerializerOptions(JsonSerializerDefaults.Web))!;
    }
}
