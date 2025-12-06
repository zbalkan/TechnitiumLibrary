using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace TechnitiumLibrary.IO
{
    public class Joint : IDisposable
    {
        #region events

        public event EventHandler Disposing;

        #endregion

        #region variables

        readonly Stream _stream1;
        readonly Stream _stream2;

        // track copy completion
        private int _pendingCopies = 2;

        #endregion

        #region constructor

        public Joint(Stream stream1, Stream stream2)
        {
            _stream1 = stream1;
            _stream2 = stream2;
        }

        #endregion

        #region IDisposable

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        bool _disposed = false;
        readonly object _disposeLock = new object();

        protected virtual void Dispose(bool disposing)
        {
            lock (_disposeLock)
            {
                if (_disposed)
                    return;

                _disposed = true; //set true before event call to prevent loop

                if (disposing)
                {
                    Disposing?.Invoke(this, EventArgs.Empty);

                    _stream1?.Dispose();
                    _stream2?.Dispose();
                }
            }
        }

        #endregion

        #region private

        private void OnCopyFinished()
        {
            if (Interlocked.Decrement(ref _pendingCopies) == 0)
                Dispose();
        }

        private async Task CopyToAsync(Stream src, Stream dst)
        {
            try
            {
                await src.CopyToAsync(dst);
            }
            finally
            {
                OnCopyFinished();
            }
        }

        #endregion

        #region public

        public void Start()
        {
            _ = CopyToAsync(_stream1, _stream2);
            _ = CopyToAsync(_stream2, _stream1);
        }

        #endregion

        #region properties

        public Stream Stream1 => _stream1;

        public Stream Stream2 => _stream2;

        #endregion
    }
}
