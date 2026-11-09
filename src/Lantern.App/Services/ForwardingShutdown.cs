namespace Lantern.App.Services;

public static class ForwardingShutdown
{
    public static async Task RunAsync(
        Func<Task> restorePeers,
        Action stopForwarding,
        Func<Task> awaitWorkers)
    {
        ArgumentNullException.ThrowIfNull(restorePeers);
        ArgumentNullException.ThrowIfNull(stopForwarding);
        ArgumentNullException.ThrowIfNull(awaitWorkers);

        List<Exception>? failures = null;

        try
        {
            await restorePeers();
        }
        catch (Exception exception)
        {
            (failures ??= []).Add(exception);
        }

        try
        {
            stopForwarding();
        }
        catch (Exception exception)
        {
            (failures ??= []).Add(exception);
        }

        // Worker completion must always be observed even if restoration or
        // cancellation fails. Native capture handles are not safe to close
        // while one of these tasks can still be using them.
        try
        {
            await awaitWorkers();
        }
        catch (Exception exception)
        {
            (failures ??= []).Add(exception);
        }

        if (failures is { Count: 1 })
        {
            System.Runtime.ExceptionServices.ExceptionDispatchInfo
                .Capture(failures[0])
                .Throw();
        }

        if (failures is { Count: > 1 })
        {
            throw new AggregateException(
                "Forwarding shutdown encountered multiple failures.",
                failures);
        }
    }
}
