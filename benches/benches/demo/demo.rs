// Creates a benchmark manager with the following default settings:
//
// - Sample size: 100 measurements
// - Warm-up time: 3 s
// - Measurement time: 5 s
// - Bootstrap size: 100 000 resamples
// - Noise threshold: 0.01 (1%)
// - Confidence level: 0.95
// - Significance level: 0.05
// - Plotting: enabled, using gnuplot if available or plotters if gnuplot is not available
// - No filter
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn fibonacci(n: u64) -> u64 {
    match n {
        0 => 1,
        1 => 1,
        n => fibonacci(n-1) + fibonacci(n-2),
    }
}

fn criterion_benchmark(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("criterion_benchmark");
    group.warm_up_time(std::time::Duration::from_secs(1));
    group.measurement_time(std::time::Duration::from_secs(2));

    group.bench_function("fib 20", |bencher| bencher.iter(|| fibonacci(black_box(20))));

    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);