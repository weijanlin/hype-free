package org.transylvania.jug.espresso.shots.d20121009;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

interface ActivityWatcher {
	void before();
	
	void after();
	
	void await(long time, TimeUnit timeUnit) throws InterruptedException, TimeoutException;
}
