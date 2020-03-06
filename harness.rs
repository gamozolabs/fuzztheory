use std::fs::File;
use std::io::Write;
use std::sync::{Arc, Mutex};
use std::collections::BTreeMap;

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

/// A fuzzing strategy
/// If `Ok()` is returned, the value contains the amount of time it took to
/// reach complete coverage and crashes.
/// If `Err()` is returned, the value contains the amount of unique coverage
/// blocks in the database at the time of the timeout (only possible with
/// a provided `timeout`)
fn start_new_fuzzer(coverage_guided: bool, workers: usize,
                    shared_inputs: bool, shared_results: bool,
                    timeout: Option<f64>) -> Result<f64, usize> {
    // If the workers are collaborative, share a single database.
    let num_input_dbs  = if shared_inputs  { 1 } else { workers };
    let num_output_dbs = if shared_results { 1 } else { workers };

    // Rng
    let mut rng = Rng::new();

    // Crash database
    let mut crashes = vec![[0; NUM_CRASHES]; num_output_dbs];

    // Coverage database
    let mut coverage = vec![[0; NUM_COVERAGE]; num_output_dbs];
    
    // Database of known inputs (fed back via coverage, starts empty)
    let mut input_db: Vec<Vec<[u8; NUM_BYTES]>> =
        vec![Vec::new(); num_input_dbs];
    
    // Fuzz input starts as all zeros
    let mut input = [0u8; NUM_BYTES];

    // Log file
    let mut fd: Option<File> = None; //Some(File::create("data.txt").expect("Failed to create data file"));

    // Vectors to hold new information discovered in a fuzz case
    let mut new_crashes  = Vec::new();
    let mut new_coverage = Vec::new();

    // Number of fuzz cases performed, shared between all workers.
    let mut cases = 0u64;

    // Fuzz loop
    loop {
        for worker in 0..workers {
            // Update number of cases (shared between all workers)
            cases += 1;

            // Get access to the worker-specfic database
            let input_db = &mut input_db[worker % num_input_dbs];
            let coverage = &mut coverage[worker % num_output_dbs];
            let crashes  = &mut crashes[worker % num_output_dbs];

            // Select an input from the input database, if it is not empty
            if coverage_guided && input_db.len() > 0 {
                input.copy_from_slice(&input_db[rng.rand() % input_db.len()]);
            }

            // Randomly replace up to 8 bytes with a random value at random
            // locations
            for _ in 0..rng.rand() % 8 + 1 {
                input[rng.rand() % input.len()] = rng.rand() as u8;
            }

            // Reset the new coverage and crash logs
            new_coverage.clear();
            new_crashes.clear();

            // Invoke the "program" we're fuzzing
            crashme(&input, coverage, crashes,
                    &mut new_coverage, &mut new_crashes);
                
            // Get the uptime (assuming workers are parallel we compute
            // this by dividing fuzz cases by number of workers)
            let uptime = cases as f64 / workers as f64;

            if let Some(timeout) = timeout {
                // Check if we hit our timeout
                if uptime >= timeout {
                    let found_coverage =
                        coverage.iter().filter(|&&x| x > 0).count();
                    return Err(found_coverage);
                }
            }

            // Save the input if it generated a crash or new coverage
            if new_coverage.len() > 0 || new_crashes.len() > 0 {
                // Save this input as we caused new coverage
                input_db.push(input);

                // Determine the number of known coverage and crashes
                let found_coverage = coverage.iter().filter(|&&x| x > 0).count();
                let found_crashes  = crashes.iter().filter(|&&x| x > 0).count();

                // Log information for graphing
                if let Some(fd) = &mut fd {
                    write!(fd, "{:15.10} {:12} {:6} {:6}\n", 
                        uptime, cases, found_coverage,
                        found_crashes).unwrap();
                    fd.flush().unwrap();
                }

                // Optionally print some status to the screen
                if false {
                    print!("Time {:15.10} Iter {:12} Cov {:5} of {:5} \
                           Crash {:5} of {:5}\n",
                        uptime, cases, found_coverage, coverage.len(),
                        found_crashes, crashes.len());
                }

                // Fuzzing complete if we found all crashes and coverage
                if found_coverage == coverage.len() &&
                        found_crashes == crashes.len() {
                    /*
                    print!("Found everything in {:10.2} | {:8}\n",
                           uptime, cases);*/
                    return Ok(uptime);
                }
            }
        }
    }
}

fn main() {
    /// Number of threads to use to perform the analysis
    const NUM_THREADS: usize = 16;

    /// Number of iterations of each fuzz attempt to perform, to generate an
    /// average value per data point.
    const AVERAGES: usize = 100;

    /// Specifies a time constraint for the fuzzer. This allows us to capture
    /// data in a format which allows generating the progress with a fixed
    /// amount of time.
    const TIME_CONSTRAINT: Option<f64> = Some(500.);

    // List of active threads such that we can join() on their completion
    let mut threads = Vec::new();

    // Generate a list of things to do
    let mut todo = Vec::new();
    for &shared_inputs in &[false, true] {
        for &shared_results in &[false, true] {
            for &guided in &[false, true] {
                for num_workers in (1..=256).step_by(1) {
                    todo.push(
                        (guided, shared_inputs, shared_results, num_workers));
                }
            }
        }
    }

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
            loop {
                // Get some work to do
                let work = {
                    print!("Todo {}\n", todo.lock().unwrap().len());
                    todo.lock().unwrap().pop()
                };

                // Check if we have work to do
                if let Some((guided, si, sr, workers)) = work {
                    // Generate the filename we're going to use for this data
                    // point.
                    let fname = format!(
                        "coverage_{}_inputshare_{}_resultshare_{}.txt",
                        guided, si, sr);

                    // Run the worker multiple times, generating the averages
                    let mut sum      = 0f64;
                    let mut sum_pow2 = 0f64;
                    for _ in 0..AVERAGES {
                        // Run the fuzz case!
                        let tmp = start_new_fuzzer(guided, workers, si, sr,
                                                   TIME_CONSTRAINT);

                        let ret = if TIME_CONSTRAINT.is_some() {
                            // Warn if we exhausted coverage within the time
                            // constraint. This may lead to unexpected results.
                            if tmp.is_ok() {
                                print!("WARNING: All coverage observed \
                                       within time constraint");
                            }

                            // Get the number of coverage records at the
                            // timeout, otherwise if it completed it's equal
                            // to the total amount of possible coverage
                            // events.
                            tmp.err().unwrap_or(NUM_COVERAGE) as f64
                        } else {
                            // Get the time it took to get full coverage and
                            // crashes
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
                        .push((workers, mean, std));
                } else {
                    // No more work, stop running the thread
                    break;
                }
            }
        }));
    }

    for thr in threads { thr.join().unwrap(); }

    // Sort and log the results
    for (filename, records) in results.lock().unwrap().iter_mut() {
        records.sort_by_key(|x| x.0);

        let mut fd = File::create(filename).unwrap();
        for (num_workers, mean, stddev) in records {
            write!(fd, "{:10} {:20.10} {:20.10}\n", num_workers, mean, stddev)
                .unwrap();
        }
    }
}

