package org.transylvania.jug.espresso.shots.d20121009;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

final class WaitingActivityWatcher implements ActivityWatcher {
	private final Object lock = new Object();
	private long counter = 0;

	@Override
	public void before() {
		synchronized (lock) {
			counter += 1;
		}
	}

	@Override
	public void after() {
		synchronized (lock) {
			counter -= 1;
			lock.notifyAll();
		}
	}

	@Override
	public void await(long duration, TimeUnit timeUnit)
			throws InterruptedException, TimeoutException {
		synchronized (lock) {
			long toWait = timeUnit.toMillis(duration);
			while (toWait > 0 && counter > 0) {
				long start = System.currentTimeMillis();
				lock.wait(toWait);
				toWait -= (System.currentTimeMillis() - start);
			}
			if (counter > 0) {
				throw new TimeoutException("Counter didn't reach zero in specified timeframe.");
			}
		}
	}

}
