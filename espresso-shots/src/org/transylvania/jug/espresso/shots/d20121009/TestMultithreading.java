package org.transylvania.jug.espresso.shots.d20121009;

import static org.junit.Assert.*;

import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;

import org.junit.Test;

public final class TestMultithreading {
	@Test
	public void testExecutor() throws Exception {
		WaitingActivityWatcher activityWatcher = new WaitingActivityWatcher();
		Executor executor = new GuardedExecutor(activityWatcher);
		int container[] = { 0 }; 
		executor.execute(getRunnable(executor, container, 0));
		activityWatcher.await(5, TimeUnit.SECONDS);
		
		assertEquals(6, container[0]);
	}

	private Runnable getRunnable(final Executor executor,
			final int[] container, final int recursionLevel) {
		return new Runnable() {
			@Override
			public void run() {
				if (recursionLevel > 5) {
					return;
				}
				container[0] += 1;
				executor.execute(getRunnable(executor, container,
						recursionLevel + 1));
			}
		};
	}
}
