package example;

final class WorkerMonitor {
    boolean timedOut(long startedAt) {
        long elapsed = System.currentTimeMillis() - startedAt;
        return elapsed > 10_000;
    }
}
