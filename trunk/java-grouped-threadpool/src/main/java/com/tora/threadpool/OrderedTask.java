package com.tora.threadpool;

public interface OrderedTask extends Runnable {
	boolean isCompatible(OrderedTask that);
}
