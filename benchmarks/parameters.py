"""Public parameter selection in the supplied manuscript, Section 6.1.1."""
import math


def public_parameters(nx_log, ny_log):
    nx, ny = 1 << nx_log, 1 << ny_log
    bins = (127 * ny + 99) // 100
    mu, t0 = 3 * nx / bins, 65536
    target = -41 * math.log(2)
    low, high = 0.0, 1.0
    while math.log(bins) - high * high * mu / (2 + high) > target:
        high *= 2
    for _ in range(80):
        delta = (low + high) / 2
        if math.log(bins) - delta * delta * mu / (2 + delta) > target:
            low = delta
        else:
            high = delta
    alpha = 1
    while True:
        degree = math.ceil((1 + high) * mu / alpha)
        log_collision = math.log(bins * t0) + (alpha + 1) * (
            1 + math.log(alpha * degree / (t0 * (alpha + 1))))
        if degree <= 2048 and alpha + 1 >= alpha * degree / t0 and log_collision <= target:
            break
        alpha += 1
    return dict(nx=nx, ny=ny, bins=bins, alpha=alpha, degree=degree,
                mu=mu, delta=high, sigma1_bits=128)
