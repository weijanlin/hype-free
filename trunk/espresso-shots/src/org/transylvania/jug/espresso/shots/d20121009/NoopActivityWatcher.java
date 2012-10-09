package org.transylvania.jug.espresso.shots.d20121009;

import java.util.concurrent.TimeUnit;

final class NoopActivityWatcher implements ActivityWatcher {
	@Override
	public void before() { }

	@Override
	public void after() { }

	@Override
	public void await(long time, TimeUnit timeUnit) {
		throw new UnsupportedOperationException("This class is not supposed to be used in tests!");
	}
}
