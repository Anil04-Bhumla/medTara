const buckets = new Map();

function cleanupBucket(key, now) {
  const bucket = buckets.get(key);

  if (!bucket) {
    return null;
  }

  if (bucket.resetAt <= now) {
    buckets.delete(key);
    return null;
  }

  return bucket;
}

function createRateLimiter({ windowMs, maxRequests, keyPrefix }) {
  return (req, res, next) => {
    const now = Date.now();
    const key = `${keyPrefix}:${req.ip || "unknown"}`;
    let bucket = cleanupBucket(key, now);

    if (!bucket) {
      bucket = {
        count: 0,
        resetAt: now + windowMs
      };
      buckets.set(key, bucket);
    }

    bucket.count += 1;

    res.setHeader("X-RateLimit-Limit", maxRequests);
    res.setHeader("X-RateLimit-Remaining", Math.max(0, maxRequests - bucket.count));
    res.setHeader("X-RateLimit-Reset", Math.ceil(bucket.resetAt / 1000));

    if (bucket.count > maxRequests) {
      return res.status(429).json({
        message: "Too many requests. Please try again shortly."
      });
    }

    next();
  };
}

module.exports = {
  createRateLimiter
};
