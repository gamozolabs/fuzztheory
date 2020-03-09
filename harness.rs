use std::fs::File;
use std::io::Write;
use std::time::Instant;
use std::sync::{Arc, Mutex};
use std::collections::{BTreeMap, BTreeSet};
    
/// Maximum number of simulated cores
const MAX_SIMULATED_CORES: usize = 2001;

struct Rng(usize);

impl Rng {
    fn new() -> Self {
        Rng(unsafe { std::arch::x86_64::_rdtsc() as usize })
    }
    fn rand(&mut self) -> usize {
        let orig = self.0;
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 17;
        self.0 ^= self.0 << 43;
        orig
    }
}

struct Fuzzer {
    /// A random number generator
    rng: Rng,

    /// Should the fuzzer use input corpus data to build upon. Eg. should it be
    /// a coverage guided fuzzer
    coverage_guided: bool,

    /// Should the fuzzer share inputs between simulated cores. This allows
    /// the cores to collaboratively share coverage information and build off
    /// eachothers progress.
    shared_inputs: bool,

    /// Should the fuzzer share results between simulated cores. This allows
    /// the coverage databases to be shared between the cores, thus making
    /// them work together towards the same goal.
    shared_results: bool,

    /// How many simulated cores should run the fuzzer. This is used to
    /// evaluate the properties of scaling the fuzzer, but does not actually
    /// cause any parallelism to be used.
    workers: usize,

    /// Database used to keep track of per-worker coverage frequencies
    coverage: Box<[[u64; NUM_COVERAGE]; MAX_SIMULATED_CORES]>,

    /// Database used to keep track of per-worker input databases
    inputs: Box<[Vec<[u8; NUM_BYTES]>; MAX_SIMULATED_CORES]>,

    /// Total number of invocations of `crashme`
    fuzz_cases: u64,

    /// Maximum amount of time to execute for
    time_constraint: Option<f64>,
}

impl Fuzzer {
    fn new() -> Self {
        let mut coverage = std::mem::ManuallyDrop::new(Vec::new());
        for _ in 0..MAX_SIMULATED_CORES {
            coverage.push([0u64; NUM_COVERAGE]);
        }
        let coverage = unsafe {
            Box::from_raw(
                coverage.as_mut_ptr() as *mut [[u64; NUM_COVERAGE]; MAX_SIMULATED_CORES])
        };

        let mut inputs = std::mem::ManuallyDrop::new(Vec::new());
        for _ in 0..MAX_SIMULATED_CORES {
            inputs.push(Vec::<[u8; NUM_BYTES]>::new());
        }
        let inputs = unsafe {
            Box::from_raw(
                inputs.as_mut_ptr() as *mut [Vec<[u8; NUM_BYTES]>; MAX_SIMULATED_CORES])
        };

        Fuzzer {
            rng:             Rng::new(),
            coverage_guided: false,
            shared_inputs:   false,
            shared_results:  false,
            workers:         1,
            fuzz_cases:      0,
            coverage:        coverage,
            inputs:          inputs,
            time_constraint: None,
        }
    }

    fn start(&mut self) -> Result<f64, usize> {
        // Get access to the RNG
        let rng = &mut self.rng;

        // If the workers are collaborative, share a single database.
        let num_input_dbs  = if self.shared_inputs  { 1 } else { self.workers };
        let num_output_dbs = if self.shared_results { 1 } else { self.workers };

        // Fuzz input starts as all zeros
        let mut input = [0u8; NUM_BYTES];

        // Number of fuzz cases performed, shared between all workers.
        let mut cases = 0u64;

        // Clear input databases
        for idb in 0..num_input_dbs {
            self.inputs[idb].clear();
        }

        // Clear result databases
        for odb in 0..num_output_dbs {
            self.coverage[odb].iter_mut().for_each(|x| *x = 0);
        }

        // Fuzz loop
        loop {
            for worker in 0..self.workers {
                // Update number of cases (shared between all workers)
                cases += 1;

                // Get access to the worker-specfic database
                let input_db = &mut self.inputs[worker % num_input_dbs];
                let coverage = &mut self.coverage[worker % num_output_dbs];

                // Select an input from the input database, if it is not empty
                if self.coverage_guided && input_db.len() > 0 {
                    input.copy_from_slice(
                        &input_db[rng.rand() % input_db.len()]);
                }

                // Randomly replace up to 8 bytes with a random value at random
                // locations
                for _ in 0..rng.rand() % 8 + 1 {
                    input[rng.rand() % input.len()] = rng.rand() as u8;
                }

                // Invoke the "program" we're fuzzing
                let new_coverage = crashme(&input, coverage);
                self.fuzz_cases += 1;
                    
                // Get the uptime (assuming workers are parallel we compute
                // this by dividing fuzz cases by number of workers)
                let uptime = cases as f64 / self.workers as f64;

                if self.time_constraint.is_some() &&
                        Some(uptime) >= self.time_constraint {
                    // Determine the number of known coverage
                    let found_coverage =
                        coverage.iter().filter(|&&x| x > 0).count();
                    return Err(found_coverage);
                }

                // Save the input if it generated new coverage
                if new_coverage {
                    // Save this input as we caused new coverage
                    input_db.push(input);

                    // Determine the number of known coverage
                    let found_coverage =
                        coverage.iter().filter(|&&x| x > 0).count();

                    // Fuzzing complete if we found all coverage
                    if found_coverage == coverage.len() {
                        return Ok(uptime);
                    }
                }
            }
        }
    }
}

fn doit(time_constraint: Option<f64>) {
    /// Number of threads to use to perform the analysis
    const NUM_THREADS: usize = 1;

    // Compute the base for an exponential function which generates
    // `MAX_X_RESOULTION` datapoints such that
    // expbase^MAX_X_RESOLUTION = MAX_SIMULATED_CORES
    const MAX_X_RESOLUTION: usize = 100;

    /// Number of iterations of each fuzz attempt to perform, to generate an
    /// average value per data point.
    const AVERAGES: usize = 1000;

    // List of active threads such that we can join() on their completion
    let mut threads = Vec::new();

    // Generate a list of things to do
    let mut todo = BTreeSet::new();
    for &shared_inputs in &[false, true] {
        for &shared_results in &[true] {
            for &guided in &[true] {
                for x in (1..=MAX_X_RESOLUTION).step_by(1) {
                    let num_workers = if false {
                        let expbase = (MAX_SIMULATED_CORES as f64)
                            .powf(1. / MAX_X_RESOLUTION as f64);
                        expbase.powf(x as f64)
                    } else {
                        (x as f64 / MAX_X_RESOLUTION as f64) *
                            MAX_SIMULATED_CORES as f64
                    } as usize;
                    todo.insert(
                        (guided, shared_inputs, shared_results, num_workers));
                }
            }
        }
    }
    let todo: Vec<_> = todo.into_iter().collect();

    // Wrap up the todo in a mutex and an arc so we can share it between
    // workers
    let todo = Arc::new(Mutex::new(todo));

    // The results which map filenames to (core, mean, stddev) tuples which
    // can be sorted before writing to a file
    let results = Arc::new(Mutex::new(BTreeMap::new()));

    for _ in 0..NUM_THREADS {
        // Make a clone of the arc so we can move it into the thread
        let todo    = todo.clone();
        let results = results.clone();

        threads.push(std::thread::spawn(move || {
            let it = Instant::now();

            let mut fuzzer = Fuzzer::new();

            loop {
                // Get some work to do
                let work = {
                    //print!("Todo {}\n", todo.lock().unwrap().len());
                    todo.lock().unwrap().pop()
                };

                // Check if we have work to do
                if let Some((guided, si, sr, workers)) = work {
                    fuzzer.coverage_guided = guided;
                    fuzzer.shared_inputs   = si;
                    fuzzer.shared_results  = sr;
                    fuzzer.workers         = workers;
                    fuzzer.time_constraint = time_constraint;

                    // Generate the filename we're going to use for this data
                    // point.
                    let fname = format!(
                        "coverage_{}_inputshare_{}_resultshare_{}.txt",
                        guided, si, sr);

                    // Track if any of the tests found all possible coverage
                    // during a time constrained mode. This will indicate that
                    // the data is invalid and should not be used.
                    let mut exhaust = false;

                    // Run the worker multiple times, generating the averages
                    let mut sum      = 0f64;
                    let mut sum_pow2 = 0f64;
                    for _ in 0..AVERAGES {
                        // Run the fuzz case!
                        let tmp = fuzzer.start();
                    
                        if false {
                            let elapsed = (Instant::now() - it).as_secs_f64();
                            print!("fcps {:10.0}\n",
                                   fuzzer.fuzz_cases as f64 / elapsed);
                        }

                        let ret = if time_constraint.is_some() {
                            if tmp.is_ok() {
                                // We ran out of coverage to gain, stop early
                                exhaust = true;
                                break;
                            }

                            // Get the number of coverage records at the
                            // timeout, otherwise if it completed it's equal
                            // to the total amount of possible coverage
                            // events.
                            tmp.err().unwrap_or(NUM_COVERAGE) as f64
                        } else {
                            // Get the time it took to get full coverage and
                            tmp.unwrap()
                        };

                        sum      += ret;
                        sum_pow2 += ret * ret;
                    }
                    let mean = sum / AVERAGES as f64;
                    let std  = ((sum_pow2 / AVERAGES as f64) - (mean * mean))
                        .sqrt();

                    // Record the results
                    results.lock().unwrap().entry(fname).or_insert(Vec::new())
                        .push((workers, mean, std, exhaust));
                } else {
                    // No more work, stop running the thread
                    break;
                }
            }
        }));
    }

    for thr in threads { thr.join().unwrap(); }

    let mut results = results.lock().unwrap();

    // Sort and log the results
    for (filename, records) in results.iter_mut() {
        records.sort_by_key(|x| x.0);

        let mut fd = File::create(filename).unwrap();
        for (num_workers, mean, stddev, exhaust) in records {
            write!(fd, "{:10} {:20.10} {:20.10} {:6}\n",
                num_workers, mean, stddev, exhaust)
                .unwrap();
        }
    }

    let shared =
        &results["coverage_true_inputshare_true_resultshare_true.txt"];
    let unshared =
        &results["coverage_true_inputshare_false_resultshare_true.txt"];
    for (shared, unshared) in shared.iter().zip(unshared.iter()) {
        assert!(shared.0 == unshared.0);

        let invalid = shared.3 | unshared.3;

        if !invalid {
            /*
            print!("{:10} {:10.6} {:15.8}\n", shared.0,
                   time_constraint.unwrap_or(0.),
                   (shared.1 - unshared.1) / unshared.1);*/
        }
    }
}

pub fn gen_heatmap() {
    /*// Get a reasonable fastest time to find all coverage
    let mut fuzzer = Fuzzer::new();
    fuzzer.coverage_guided = true;
    fuzzer.shared_inputs   = true;
    fuzzer.shared_results  = true;
    fuzzer.workers         = MAX_SIMULATED_CORES;

    print!("Calibating upper bound\n");
    let tmp = fuzzer.start();
    panic!("{:?}\n", tmp);*/

    const MAX_Y_RESOLUTION: usize = 100;
    const MAX_Y_POINT: f64 = 1.0;

    for timeout in 1..=MAX_Y_RESOLUTION {
        let timeout = if false {
            let expbase = (2. as f64)
                .powf(1.0 / MAX_Y_RESOLUTION as f64);
            expbase.powf(timeout as f64) - 1.
        } else {
            (timeout as f64 / MAX_Y_RESOLUTION as f64) * MAX_Y_POINT
        };
        //print!("{}\n", timeout);
        doit(Some(timeout));
    }
}

pub fn perf() {
    let mut fuzzer = Fuzzer::new();

    let it = Instant::now();
    loop {
        fuzzer.coverage_guided = true;
        fuzzer.shared_inputs   = false;
        fuzzer.shared_results  = false;
        fuzzer.workers         = 1;
        fuzzer.start();

        let elapsed = (Instant::now() - it).as_secs_f64();
        print!("{:12.2} fuzz cases/second\n", fuzzer.fuzz_cases as f64 / elapsed);
    }
}

fn main() {
    perf();
}

