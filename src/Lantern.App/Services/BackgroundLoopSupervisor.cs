namespace Lantern.App.Services;

public static class BackgroundLoopSupervisor
{
    public static async Task RunAsync(
        string name,
        Func<Task> loop,
        CancellationToken cancellationToken,
        Action<string, Exception> onFailure)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        ArgumentNullException.ThrowIfNull(loop);
        ArgumentNullException.ThrowIfNull(onFailure);

        try
        {
            await loop();
            if (!cancellationToken.IsCancellationRequested)
            {
                onFailure(
                    name,
                    new InvalidOperationException($"{name} stopped unexpectedly."));
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (Exception exception)
        {
            if (!cancellationToken.IsCancellationRequested)
            {
                onFailure(name, exception);
            }
        }
    }
}
