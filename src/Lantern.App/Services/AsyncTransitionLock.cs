namespace Lantern.App.Services;

/// <summary>
/// Serializes lifecycle transitions. The returned lease releases the gate once,
/// including when a transition exits through an exception.
/// </summary>
public sealed class AsyncTransitionLock
{
    private readonly SemaphoreSlim semaphore = new(1, 1);

    public async ValueTask<Lease> EnterAsync(CancellationToken cancellationToken = default)
    {
        await semaphore.WaitAsync(cancellationToken);
        return new Lease(semaphore);
    }

    public sealed class Lease : IDisposable
    {
        private SemaphoreSlim? owner;

        internal Lease(SemaphoreSlim owner)
        {
            this.owner = owner;
        }

        public void Dispose()
        {
            Interlocked.Exchange(ref owner, null)?.Release();
        }
    }
}
