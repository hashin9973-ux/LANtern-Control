using Lantern.App.Services;
using System.Text.Json;
using Xunit;

namespace Lantern.App.Tests;

public sealed class EngineDiagnosticLogTests
{
    [Fact]
    public void Write_AppendsStructuredJsonLinesWithLifecycleContext()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"lantern-tests-{Guid.NewGuid():N}");
        var path = Path.Combine(directory, "engine.jsonl");
        try
        {
            var logger = new EngineDiagnosticLog(path);
            logger.Write(
                "controller.faulted",
                "Npcap capture loop",
                "Wi-Fi",
                "degraded",
                "GetNextPacket returned an error",
                new IOException("adapter disappeared"));

            var entry = JsonDocument.Parse(File.ReadAllText(path)).RootElement;
            Assert.Equal("controller.faulted", entry.GetProperty("event").GetString());
            Assert.Equal("Npcap capture loop", entry.GetProperty("component").GetString());
            Assert.Equal("Wi-Fi", entry.GetProperty("adapter").GetString());
            Assert.Equal("degraded", entry.GetProperty("state").GetString());
            Assert.Equal(
                "GetNextPacket returned an error",
                entry.GetProperty("reason").GetString());
            Assert.Equal(
                typeof(IOException).FullName,
                entry.GetProperty("exceptionType").GetString());
            Assert.Contains("adapter disappeared", entry.GetProperty("exceptionDetails").GetString());
        }
        finally
        {
            if (Directory.Exists(directory))
            {
                Directory.Delete(directory, recursive: true);
            }
        }
    }

    [Fact]
    public void Write_DoesNotThrowWhenLogPathCannotBeWritten()
    {
        var logger = new EngineDiagnosticLog(
            Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"), "missing", "engine.jsonl"));

        var exception = Record.Exception(() =>
            logger.Write("controller.stopped", "lifecycle", null, "stopped"));

        Assert.Null(exception);
    }
}
