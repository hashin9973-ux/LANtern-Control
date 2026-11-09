namespace Lantern.App.Services;

public static class ArpEnforcementRetry
{
    public const int MaxAttempts = 3;

    public static async Task ExecuteAsync(
        Action operation,
        CancellationToken cancellationToken,
        Action<int, Exception>? onRetry = null,
        TimeSpan? retryDelay = null)
    {
        ArgumentNullException.ThrowIfNull(operation);

        Exception? lastFailure = null;
        for (var attempt = 1; attempt <= MaxAttempts; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                operation();
                return;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception exception) when (exception is not OperationCanceledException)
            {
                if (cancellationToken.IsCancellationRequested)
                {
                    throw new OperationCanceledException(cancellationToken);
                }

                lastFailure = exception;
                if (attempt == MaxAttempts)
                {
                    break;
                }

                onRetry?.Invoke(attempt + 1, exception);
                var initialDelay = retryDelay ?? TimeSpan.FromMilliseconds(250);
                if (initialDelay <= TimeSpan.Zero)
                {
                    throw new ArgumentOutOfRangeException(
                        nameof(retryDelay),
                        "Retry delay must be positive.");
                }

                await Task.Delay(TimeSpan.FromTicks(initialDelay.Ticks * attempt), cancellationToken);
            }
        }

        throw new InvalidOperationException(
            $"ARP enforcement failed after {MaxAttempts} attempts.",
            lastFailure);
    }
}
