using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Threading.Tasks;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary
{
    [TestClass]
    public sealed class TaskPoolTests
    {
        [TestMethod]
        public async Task TryQueueTask_ShouldExecuteQueuedTask()
        {
            // GIVEN
            var pool = new TaskPool(queueSize: 10, maximumConcurrencyLevel: 2);
            var completer = new TaskCompletionSource<bool>();

            // WHEN
            var queued = pool.TryQueueTask(_ =>
            {
                completer.SetResult(true);
                return Task.CompletedTask;
            });

            // THEN
            Assert.IsTrue(queued, "Task should be accepted into queue.");
            Assert.IsTrue(await completer.Task, "Task must execute.");
        }

        [TestMethod]
        public async Task ShouldProcessMultipleTasksConcurrently_WhenAllowed()
        {
            // GIVEN
            var parallelism = Environment.ProcessorCount;
            var pool = new TaskPool(queueSize: 64, maximumConcurrencyLevel: parallelism);

            var counter = 0;
            var completion = new TaskCompletionSource<bool>();
            var lockObj = new object();

            int total = parallelism;

            // WHEN
            for (int i = 0; i < total; i++)
            {
                pool.TryQueueTask(_ =>
                {
                    lock (lockObj)
                        counter++;

                    if (counter == total)
                        completion.SetResult(true);

                    return Task.CompletedTask;
                });
            }

            // THEN
            Assert.IsTrue(await completion.Task, "All tasks must execute.");
            Assert.AreEqual(total, counter, "All queued tasks must run.");
        }

        [TestMethod]
        public async Task TasksShouldStopAfterDispose()
        {
            // GIVEN
            var pool = new TaskPool(queueSize: 10, maximumConcurrencyLevel: 1);

            var executedBeforeDispose = new TaskCompletionSource<bool>();
            var wasExecutedAfterDispose = false;

            pool.TryQueueTask(_ =>
            {
                executedBeforeDispose.SetResult(true);
                return Task.CompletedTask;
            });

            await executedBeforeDispose.Task;

            // WHEN
            pool.Dispose();
            var acceptedPostDispose = pool.TryQueueTask(_ =>
            {
                wasExecutedAfterDispose = true;
                return Task.CompletedTask;
            });

            // THEN
            Assert.IsFalse(acceptedPostDispose, "After disposal, queue must reject writes.");
            Assert.IsFalse(wasExecutedAfterDispose, "Tasks queued after Dispose must not run.");
        }

        [TestMethod]
        public void Ctor_ShouldUseDefaultConcurrency_WhenValueIsLessThanOne()
        {
            // GIVEN + WHEN
            var pool = new TaskPool(queueSize: 10, maximumConcurrencyLevel: -1);

            // THEN
            Assert.IsGreaterThanOrEqualTo(1,
pool.MaximumConcurrencyLevel, "Concurrency must fallback to processor count.");
        }

        [TestMethod]
        public void TryQueueTask_ShouldThrow_WhenTaskIsNull()
        {
            // GIVEN
            var pool = new TaskPool();

            // WHEN + THEN
            Assert.ThrowsExactly<ArgumentNullException>(() => pool.TryQueueTask(null));
        }

        [TestMethod]
        public async Task TaskShouldReceiveStateObject()
        {
            // GIVEN
            var pool = new TaskPool();
            var completion = new TaskCompletionSource<bool>();

            var expectedState = "STATE";
            var capturedState = default(string);

            // WHEN
            pool.TryQueueTask(obj =>
            {
                capturedState = obj as string;
                completion.SetResult(true);
                return Task.CompletedTask;
            }, expectedState);

            await completion.Task;

            // THEN
            Assert.AreEqual(expectedState, capturedState, "State parameter must propagate through execution.");
        }

        [TestMethod]
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "MSTEST0032:Assertion condition is always true", Justification = "Multiple Dispose must not throw")]
        public void DisposeMustBeIdempotent()
        {
            // GIVEN
            var pool = new TaskPool();

            // WHEN
            pool.Dispose();
            pool.Dispose();
            pool.Dispose();

            // THEN
            Assert.IsTrue(true, "Dispose must not throw.");
        }
    }
}
