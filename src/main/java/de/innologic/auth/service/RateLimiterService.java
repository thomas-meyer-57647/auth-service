package de.innologic.auth.service;

import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

@Service
public class RateLimiterService {

    private final ConcurrentMap<String, Deque<Long>> requestTimestamps = new ConcurrentHashMap<>();

    public boolean tryConsume(String clientId, String bucketKey, int maxRequests, Duration window) {
        String combinedKey = clientId + ":" + bucketKey;
        Deque<Long> timestamps = requestTimestamps.computeIfAbsent(combinedKey, key -> new ArrayDeque<>());
        long now = Instant.now().toEpochMilli();
        long cutoff = now - window.toMillis();
        synchronized (timestamps) {
            while (!timestamps.isEmpty() && timestamps.peekFirst() < cutoff) {
                timestamps.pollFirst();
            }
            if (timestamps.size() >= maxRequests) {
                return false;
            }
            timestamps.addLast(now);
            return true;
        }
    }

    public void reset() {
        requestTimestamps.clear();
    }

    public void clear(String clientId, String bucketKey) {
        requestTimestamps.remove(clientId + ":" + bucketKey);
    }

    public Map<String, Integer> snapshotByEndpoint() {
        Map<String, Integer> summary = new LinkedHashMap<>();
        requestTimestamps.forEach((combinedKey, timestamps) -> {
            String bucketKey = combinedKey.contains(":") ? combinedKey.substring(combinedKey.indexOf(":") + 1) : combinedKey;
            synchronized (timestamps) {
                summary.merge(bucketKey, timestamps.size(), Integer::sum);
            }
        });
        return summary;
    }
}
