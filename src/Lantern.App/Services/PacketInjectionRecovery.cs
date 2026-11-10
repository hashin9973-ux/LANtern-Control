namespace Lantern.App.Services;

/// <summary>
/// Executes a packet send with one bounded handle-reopen attempt. A replacement
/// handle is returned only after its send function accepts the exact same frame
/// that failed on the previous handle.
/// </summary>
public static class PacketInjectionRecovery
{
    public static THandle Send<THandle>(
        THandle? currentHandle,
        Func<THandle> openHandle,
        Action<THandle, byte[]> sendPacket,
        Action<THandle> closeHandle,
        byte[] frame,
        out bool recovered,
        Action<Exception>? onAttemptFailure = null,
        Action<Exception>? onCleanupFailure = null)
        where THandle : class
    {
        ArgumentNullException.ThrowIfNull(openHandle);
        ArgumentNullException.ThrowIfNull(sendPacket);
        ArgumentNullException.ThrowIfNull(closeHandle);
        ArgumentNullException.ThrowIfNull(frame);
        if (frame.Length == 0)
        {
            throw new ArgumentException("An injection frame cannot be empty.", nameof(frame));
        }

        THandle? attemptedHandle = currentHandle;
        try
        {
            attemptedHandle ??= openHandle() ??
                throw new InvalidOperationException("The injection-handle factory returned null.");
            sendPacket(attemptedHandle, frame);
            recovered = false;
            return attemptedHandle;
        }
        catch (Exception initialFailure)
        {
            Notify(onAttemptFailure, initialFailure);
            TryClose(attemptedHandle, closeHandle, onCleanupFailure);

            THandle? replacement = null;
            try
            {
                replacement = openHandle() ??
                    throw new InvalidOperationException("The replacement injection-handle factory returned null.");
                sendPacket(replacement, frame);
                recovered = true;
                return replacement;
            }
            catch (Exception recoveryFailure)
            {
                Notify(onAttemptFailure, recoveryFailure);
                TryClose(replacement, closeHandle, onCleanupFailure);
                recovered = false;
                throw new InvalidOperationException(
                    "Packet injection failed on the active handle and after opening a replacement handle.",
                    new AggregateException(initialFailure, recoveryFailure));
            }
        }
    }

    private static void TryClose<THandle>(
        THandle? handle,
        Action<THandle> closeHandle,
        Action<Exception>? onCleanupFailure)
        where THandle : class
    {
        if (handle is null)
        {
            return;
        }

        try
        {
            closeHandle(handle);
        }
        catch (Exception cleanupFailure)
        {
            Notify(onCleanupFailure, cleanupFailure);
        }
    }

    private static void Notify(
        Action<Exception>? observer,
        Exception exception)
    {
        if (observer is null)
        {
            return;
        }

        try
        {
            observer(exception);
        }
        catch (Exception)
        {
            // Diagnostics must never prevent bounded packet recovery.
        }
    }
}
