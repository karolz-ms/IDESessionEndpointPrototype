using System;
using System.Buffers;
using System.Net.WebSockets;
using System.Threading;
using System.Threading.Tasks;

namespace VsSessionClient;

internal class WebSocketReceiver
{
    public static async Task<(IDisposable, Memory<byte>, WebSocketMessageType)> ReceiveAll(WebSocket ws, CancellationToken ct)
    {
        var memoryPool = MemoryPool<byte>.Shared;
        var bufferSize = 1024;
        var buffer = memoryPool.Rent(bufferSize);
        var offset = 0;
        WebSocketMessageType messageType = WebSocketMessageType.Text;
        ;
        while (true)
        {
            var result = await ws.ReceiveAsync(buffer.Memory.Slice(offset), ct);
            offset += result.Count;
            messageType = result.MessageType;

            if (result.EndOfMessage)
                break;

            if (offset >= bufferSize)
            {
                // Buffer is full, rent a larger one
                var newBuffer = memoryPool.Rent(bufferSize * 2);
                buffer.Memory.CopyTo(newBuffer.Memory);
                buffer.Dispose();
                buffer = newBuffer;
                bufferSize *= 2;
            }
        }

        return (buffer, buffer.Memory.Slice(0, offset), messageType);
    }
}
