namespace Lantern.App.Services;

public static class ArpEnforcementRetry
{
    public const int MaxAttempts = 3;

    public static async Task ExecuteAsync(
        Action operation,
        CancellationToken cancellationToken,
        Action<int, Exception>? onRetry = null)
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
            catch (Exception) when (cancellationToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception exception) when (exception is not OperationCanceledException)
            {
                lastFailure = exception;
                if (attempt == MaxAttempts)
                {
                    break;
                }

                onRetry?.Invoke(attempt + 1, exception);
                await Task.Delay(TimeSpan.FromMilliseconds(250 * attempt), cancellationToken);
            }
        }

        throw new InvalidOperationException(
            $"ARP enforcement failed after {MaxAttempts} attempts.",
            lastFailure);
    }
}
