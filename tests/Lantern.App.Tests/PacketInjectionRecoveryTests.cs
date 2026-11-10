using Lantern.App.Services;
using Xunit;

namespace Lantern.App.Tests;

public sealed class PacketInjectionRecoveryTests
{
    [Fact]
    public void Send_ReopensAndResendsTheSameFrameBeforeReportingRecovery()
    {
        var failedHandle = new FakeHandle(1);
        var replacementHandle = new FakeHandle(2);
        var sendAttempts = new List<int>();
        var failures = new List<Exception>();
        var frame = new byte[] { 0x01, 0x02, 0x03 };

        var result = PacketInjectionRecovery.Send(
            failedHandle,
            () => replacementHandle,
            (handle, sentFrame) =>
            {
                sendAttempts.Add(handle.Id);
                Assert.Same(frame, sentFrame);
                if (handle.Id == failedHandle.Id)
                {
                    throw new IOException("The original handle stopped sending.");
                }
            },
            handle => handle.Closed = true,
            frame,
            out var recovered,
            failures.Add);

        Assert.Same(replacementHandle, result);
        Assert.True(recovered);
        Assert.True(failedHandle.Closed);
        Assert.False(replacementHandle.Closed);
        Assert.Equal([1, 2], sendAttempts);
        Assert.Single(failures);
    }

    [Fact]
    public void Send_WhenReplacementAlsoFails_ClosesBothHandlesAndPreservesBothFailures()
    {
        var failedHandle = new FakeHandle(1);
        var replacementHandle = new FakeHandle(2);
        var sendAttempts = new List<int>();
        var cleanupFailures = new List<Exception>();

        var exception = Assert.Throws<InvalidOperationException>(() =>
        {
            _ = PacketInjectionRecovery.Send(
                failedHandle,
                () => replacementHandle,
                (handle, _) =>
                {
                    sendAttempts.Add(handle.Id);
                    throw new IOException($"Handle {handle.Id} cannot send.");
                },
                handle => handle.Closed = true,
                [0x55],
                out _,
                onCleanupFailure: cleanupFailures.Add);
        });

        Assert.True(failedHandle.Closed);
        Assert.True(replacementHandle.Closed);
        Assert.Equal([1, 2], sendAttempts);
        var failures = Assert.IsType<AggregateException>(exception.InnerException);
        Assert.Equal(2, failures.InnerExceptions.Count);
        Assert.Contains("Handle 1", failures.InnerExceptions[0].Message);
        Assert.Contains("Handle 2", failures.InnerExceptions[1].Message);
        Assert.Empty(cleanupFailures);
    }

    [Fact]
    public void Send_WithoutCurrentHandle_OpensAndSendsWithoutAnUnnecessaryReopen()
    {
        var openedHandle = new FakeHandle(1);
        var openCount = 0;
        var sendCount = 0;

        var result = PacketInjectionRecovery.Send(
            currentHandle: null,
            openHandle: () =>
            {
                openCount++;
                return openedHandle;
            },
            sendPacket: (handle, _) =>
            {
                Assert.Same(openedHandle, handle);
                sendCount++;
            },
            closeHandle: handle => handle.Closed = true,
            frame: [0xAA],
            out var recovered);

        Assert.Same(openedHandle, result);
        Assert.False(recovered);
        Assert.Equal(1, openCount);
        Assert.Equal(1, sendCount);
        Assert.False(openedHandle.Closed);
    }

    [Fact]
    public void Send_ContinuesRecoveryWhenClosingTheFailedHandleThrows()
    {
        var failedHandle = new FakeHandle(1);
        var replacementHandle = new FakeHandle(2);
        Exception? reportedCleanupFailure = null;

        var result = PacketInjectionRecovery.Send(
            failedHandle,
            () => replacementHandle,
            (handle, _) =>
            {
                if (handle.Id == failedHandle.Id)
                {
                    throw new IOException("The original send failed.");
                }
            },
            handle =>
            {
                if (handle.Id == failedHandle.Id)
                {
                    throw new IOException("The original handle could not close.");
                }

                handle.Closed = true;
            },
            [0xBB],
            out var recovered,
            onCleanupFailure: exception => reportedCleanupFailure = exception);

        Assert.Same(replacementHandle, result);
        Assert.True(recovered);
        Assert.IsType<IOException>(reportedCleanupFailure);
        Assert.False(failedHandle.Closed);
    }

    private sealed class FakeHandle(int id)
    {
        public int Id { get; } = id;

        public bool Closed { get; set; }
    }
}
