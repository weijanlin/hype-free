package org.transylvania.jug.espresso.shots.d20121009;

import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

final class GuardedExecutor implements Executor {
	private final ActivityWatcher activityWatcher;
	private final Executor executor;

	GuardedExecutor(ActivityWatcher activityWatcher) {
		this.activityWatcher = activityWatcher;
		this.executor = Executors.newSingleThreadExecutor();
	}
	
	@Override
	public void execute(final Runnable command) {
		activityWatcher.before();
		executor.execute(new Runnable() {
			@Override
			public void run() {
				try {
					command.run();
				} finally {
					activityWatcher.after();
				}
			}
		});
	}
}
