package org.transylvania.jug.espresso.shots.d20110221;

import java.util.*;
import java.util.concurrent.*;
import org.junit.*;
import static org.junit.Assert.*;

public class TestSizeExecutionSpeed {
	@Test
	public void testNonblockingQueue() {
		Collection<Integer> largeQueue = fill(1000000, new ConcurrentLinkedQueue<Integer>()),
			smallQueue = fill(10, new ConcurrentLinkedQueue<Integer>());
		
		long longTime = measureSizeInvocationTime(largeQueue),
			shortTime = measureSizeInvocationTime(smallQueue);
		assertTrue( 10*shortTime < longTime );
	}

	@Test
	public void testNavigableSet() {
		NavigableSet<Integer> largeSet = fill(100000, new TreeSet<Integer>()),
			smallSet = fill(10, new TreeSet<Integer>());
		SortedSet<Integer> largeSubset = largeSet.tailSet(1),
			smallSubset = smallSet.tailSet(1);
		
		long longTime = measureSizeInvocationTime(largeSubset),
			shortTime = measureSizeInvocationTime(smallSubset);
		assertTrue( 10*shortTime < longTime );
	}

	private long measureSizeInvocationTime(Collection<Integer> coll) {
		long sum = 0;
		for (int i = 0; i < 10; ++i) {
			long start = System.nanoTime();
			coll.size();
			sum += System.nanoTime() - start;
		}
		return sum / 10;
	}
	
	private static <T extends Collection<Integer>> T fill(int count, T target) {
		for (int i = 0; i < count; ++i) { target.add(Integer.valueOf(i)); }
		return target;
	}
}
