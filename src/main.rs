use std::io;
use std::collections::BTreeSet;
use std::process::Command;

struct Rng(usize);
impl Rng {
    fn new() -> Self { 
        //Rng(unsafe { std::arch::x86_64::_rdtsc() as usize })
        Rng(0x2f7151ffd59720b3)
    }
    fn rand(&mut self) -> usize {
        let orig = self.0;
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 17;
        self.0 ^= self.0 << 43;
        orig
    }
}

fn proggen() -> io::Result<()> {
    // Create an RNG
    let mut rng = Rng::new();

    // Create a string to contain our output program source code
    let mut program = String::new();

    // A set containing all of the bit indicies which have been used from the
    // input file. This allows us to allocate out bit slices from the input
    // file to generate different conditions.
    let mut used_bits: BTreeSet<usize> = BTreeSet::new();

    // Maximum size of the input file in bits. This means bit indicies which
    // are used for the input of the program always are in a range of
    // [0, MAX_INPUT_SIZE_BITS).
    const MAX_INPUT_SIZE_BITS: usize = 256;

    // !!! NOTE !!!
    // All the below chances are the "one in <val>" chance figures.

    // Chance of generating an if statement
    const IF_CHANCE: usize = 4;
    
    // Chance of ending the current if statement (ending the block)
    const END_BLOCK_CHANCE: usize = 4;

    // Chance that on the ending of a block, a crashing memory access is emit
    const CRASH_CHANCE: usize = 8;

    // Chance that a crash condition can occur without coverage. This simulates
    // an out-of-bounds access where the block may be valid in many situations.
    // We simply omit generating coverage events.
    const NON_COVERAGE_CRASH_CHANCE: usize = 16;

    // Chance of ending the program generation, finishing all unfinished blocks
    // unconditionally.
    // This is effectively what limits the size of the program (and the
    // `MAX_INPUT_SIZE_BITS`)
    const DONE_CHANCE: usize = 128;

    // Minimum number of crashes to generate (exiting the loop will not occur
    // until at least this many crashes are generated)
    const MIN_CRASHES: u64 = 200;
    
    // Minimum number of blocks to generate (exiting the loop will not occur
    // until at least this many blocks are generated).
    const MIN_BLOCKS: u64 = 5000;

    // Maximum number of bit allocation failures until we finally give up.
    // This will abruptly terminate the program (even prior to MIN_CRASHES and
    // MAX_CRASHES), if we were unable to have more bits to use for program
    // flow.
    //
    // Allowing failures effectively makes deeper branches less complex, which
    // typically will make the graph not very realistic to a real program as
    // it can go exponential as subsequent branches are easier to solve.
    const MAX_ALLOC_FAILURES: usize = 1;

    // Macro which will find unused bits by randomly generating bit slices and
    // only returning once a bit slice is found that is not already used.
    // Further, this will only look for bit slices which fit inside of a
    // byte value which is aligned. This ensures that the bit slice can be a
    // simple mask and compare against a single volatile byte read.
    macro_rules! find_unused_bits {
        ($num_bits:expr, $timeout:expr) => {{
            // Make sure the number of bits fits within a byte
            assert!($num_bits > 0 && $num_bits <= 8,
                    "Invalid bit size for find_unused_bits");

            let mut iters = 0u64;
            'try_another_slice: loop {
                // Give up on the search after a user-defined threshold
                if iters >= $timeout {
                    break None;
                }
                iters += 1;

                // Find the start and end bit indicies [bit_start, bit_end]
                let bit_start = rng.rand() % MAX_INPUT_SIZE_BITS;
                let bit_end   = bit_start + $num_bits - 1;

                // Bit overflow or bits spanning a byte boundary
                if bit_end >= MAX_INPUT_SIZE_BITS ||
                        (bit_start / 8) != (bit_end / 8) {
                    continue 'try_another_slice;
                }

                // Go through each bit index looking for if it is used
                for bit in bit_start..bit_end + 1 {
                    if used_bits.contains(&bit) {
                        continue 'try_another_slice;
                    }
                }

                // At this point the slice is free! Mark it as used!
                for bit in bit_start..bit_end + 1 {
                    used_bits.insert(bit);
                }

                break Some((bit_start, bit_end));
            }
        }}
    }

    // Tab/nested if depth of the program
    let mut depth = 1;

    // Number of blocks
    let mut num_blocks = 0u64;

    // Number of crashes
    let mut num_crashes = 0u64;
    
    // Tab in the program by `depth` tabs
    macro_rules! tab { () => { for _ in 0..depth { program += "    "; } } }

    // Generate a coverage record based on the unique block ID, then update
    // the number of blocks
    macro_rules! coverage {
        () => {
            tab!();
            program += &format!(
                "if _coverage[{}] == 0 {{ _new_coverage.push({}) }}\n",
                num_blocks, num_blocks);
            tab!();
            program += &format!("_coverage[{}] += 1;\n", num_blocks);
            num_blocks += 1;
        }
    }
    
    // Generate a crash record based on the unique crash ID, then update the
    // number of unique crashes
    macro_rules! crash {
        () => {
            tab!();
            program += &format!(
                "if _crashes[{}] == 0 {{ _new_crashes.push({}) }}\n",
                num_crashes, num_crashes);

            tab!();
            program += &format!("_crashes[{}] += 1;\n", num_crashes);

            // Crashes should break out of the function to allow for a new fuzz
            // case
            tab!();
            program += "return;\n";

            num_crashes += 1;
        }
    }

    // The good stuff
    // Returns (new_coverage, new_crash)
    program += "fn crashme(_input: &[u8], _coverage: &mut [u64], \
        _crashes: &mut [u64], _new_coverage: &mut Vec<usize>,
        _new_crashes: &mut Vec<usize>) {\n";

    coverage!();

    // Number of bit allocation failures
    let mut alloc_failures = 0;

    loop {
        // Random chance to generate an if statement
        if rng.rand() % IF_CHANCE == 0 {
            if let Some((start, end)) =
                    find_unused_bits!(rng.rand() % 8 + 1, 1000) {

                let start_byte = start / 8;
                let start_bit  = start % 8;
                let end_bit    = end   % 8;

                // Generate a byte mask for these bits
                let mask = (!0u8 >> start_bit) << start_bit;
                let mask = (mask << (7 - end_bit)) >> (7 - end_bit);

                // Generate a target value for these bits
                let target = rng.rand() as u8 & mask;


                tab!();
                program += &format!(
                    "if _input[{}] & {:#010b} == {:#010b} {{\n",
                    start_byte, mask, target);
                depth += 1;

                // Random chance of creating a conditional crash that cannot
                // be tracked with coverage events. Eg. an OOB access
                if rng.rand() % NON_COVERAGE_CRASH_CHANCE == 0 {
                    crash!();
                    depth -= 1;
                    tab!();
                    program += "}\n";
                } else {
                    coverage!();
                }
            } else {
                alloc_failures += 1;
                if alloc_failures >= MAX_ALLOC_FAILURES {
                    // Fail if there were too many failed attempts to find
                    // free bits.
                    break;
                }
            }
        }
 
        // Random chance to de-tab
        if depth > 1 && rng.rand() % END_BLOCK_CHANCE == 0 {
            // Random chance of a crashing target
            if rng.rand() % CRASH_CHANCE == 0 {
                crash!();
            }

            depth -= 1;
            tab!();
            program += "}\n";
        }

        // Random chance to end the loop
        if num_crashes >= MIN_CRASHES && num_blocks >= MIN_BLOCKS &&
            rng.rand() % DONE_CHANCE == 0 { break; }
    }

    // Clean out brackets
    while depth > 1 {
        depth -= 1;
        tab!();
        program += "}\n";
    }

    // End the program
    program += "}\n";

    program += &format!("const NUM_CRASHES:  usize = {};\n", num_crashes);
    program += &format!("const NUM_COVERAGE: usize = {};\n", num_blocks);
    program += &format!("const NUM_BYTES:    usize = {};\n",
        ((MAX_INPUT_SIZE_BITS + 7) & !7) / 8);

    // Write out the program
    std::fs::write("test.rs",
                   std::fs::read_to_string("harness.rs")? + &program)?;

    // Build the program
    assert!(Command::new("rustc")
        .arg("-O")
        .arg("test.rs")
        .status()?.success());

    // Print out the program "complexity"
    print!("Program complexity:\n\
        Blocks:  {}\n\
        Crashes: {}\n", num_blocks, num_crashes);
   
    // Run the program
    assert!(Command::new("./test")
        .arg("test.rs")
        .status()?.success());
    
    Ok(())
}

fn main() -> io::Result<()> {
    proggen()
}

