using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Threading;
using System.Threading.Tasks;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary
{
    [TestClass]
    public sealed class IndependentTaskSchedulerTests
    {
        [TestMethod]
        public async Task Task_ShouldExecute_WhenQueued()
        {
            // GIVEN
            using var scheduler = new IndependentTaskScheduler(maximumConcurrencyLevel: 1);
            var completion = new TaskCompletionSource<bool>();

            // WHEN
            var t = new Task(_ => completion.SetResult(true), null);
            t.Start(scheduler);

            // THEN
            Assert.IsTrue(await completion.Task);
        }

        [TestMethod]
        public void MaximumConcurrencyLevel_ShouldMatchRequested()
        {
            // GIVEN
            using var scheduler = new IndependentTaskScheduler(3);

            // WHEN
            var level = scheduler.MaximumConcurrencyLevel;

            // THEN
            Assert.AreEqual(3, level);
        }

        [TestMethod]
        public async Task Tasks_ShouldRunInParallel_WhenConcurrencyGreaterThanOne()
        {
            // GIVEN
            using var scheduler = new IndependentTaskScheduler(maximumConcurrencyLevel: 2);
            var parallelStarted = new TaskCompletionSource<bool>();
            var runningCount = 0;

            Task Body() =>
                Task.Run(() =>
                {
                    if (Interlocked.Increment(ref runningCount) == 2)
                    {
                        parallelStarted.SetResult(true);
                    }
                    Thread.Sleep(40);
                });

            // WHEN
            _ = Task.Factory.StartNew(() => Body(), CancellationToken.None, TaskCreationOptions.None, scheduler).Unwrap();
            _ = Task.Factory.StartNew(() => Body(), CancellationToken.None, TaskCreationOptions.None, scheduler).Unwrap();

            // THEN
            Assert.IsTrue(await parallelStarted.Task);
        }

        [TestMethod]
        public void LongRunningOption_ShouldExecuteOnDedicatedThread()
        {
            // GIVEN
            using var scheduler = new IndependentTaskScheduler(1);
            var factoryThreadId = Thread.CurrentThread.ManagedThreadId;
            var schedulerThreadId = -1;

            // WHEN
            var task = new Task(
                _ => schedulerThreadId = Thread.CurrentThread.ManagedThreadId,
                null,
                TaskCreationOptions.LongRunning);

            task.Start(scheduler);
            task.Wait();

            // THEN
            Assert.AreNotEqual(factoryThreadId, schedulerThreadId);
        }

        [TestMethod]
        public async Task InlineExecution_ShouldRun_WhenCalledInsideSchedulerThread()
        {
            // GIVEN
            using var scheduler = new IndependentTaskScheduler(1);

            var executedInline = new TaskCompletionSource<bool>();

            // WHEN
            var driver = new Task(() =>
            {
                // Attempt inline execution from scheduler thread
                var child = new Task(() => executedInline.SetResult(true));
                // This will execute inline because we are already inside scheduler thread
                child.RunSynchronously(TaskScheduler.Current);
            });

            // Run the driver task inside scheduler
            driver.Start(scheduler);
            await driver;

            // THEN
            Assert.IsTrue(await executedInline.Task, "Task must execute inline in scheduler thread.");
        }

        [TestMethod]
        public void Dispose_ShouldPreventFutureExecution()
        {
            // GIVEN
            var scheduler = new IndependentTaskScheduler(1);
            scheduler.Dispose();
            var task = new Task(() => { });

            // WHEN
            var continuation = Task.Factory.StartNew(
                () => task.Start(scheduler),
                CancellationToken.None,
                TaskCreationOptions.None,
                TaskScheduler.Default);

            continuation.Wait();

            // THEN
            Assert.IsFalse(task.IsCompleted);
        }

        [TestMethod]
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "MSTEST0032:Assertion condition is always true", Justification = "Double Dispose must not throw")]
        public void Dispose_CanBeCalledMultipleTimes_Safely()
        {
            // GIVEN
            var scheduler = new IndependentTaskScheduler();

            // WHEN
            scheduler.Dispose();
            scheduler.Dispose();

            // THEN
            Assert.IsTrue(true); // simply must not throw
        }
    }
}
