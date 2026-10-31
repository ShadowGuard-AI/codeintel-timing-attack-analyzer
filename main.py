import argparse
import time
import logging
import os
import sys
import ast
import subprocess

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.

    Returns:
        argparse.ArgumentParser: The argument parser object.
    """
    parser = argparse.ArgumentParser(description="Identifies potential timing attack vulnerabilities by analyzing the execution time of code blocks.")
    parser.add_argument("target_file", help="The Python file to analyze.")
    parser.add_argument("--iterations", type=int, default=100, help="Number of iterations to run for timing analysis (default: 100).")
    parser.add_argument("--threshold", type=float, default=0.05, help="Threshold for timing difference (as a percentage) to flag as a potential vulnerability (default: 0.05).")
    parser.add_argument("--output", type=str, default="timing_analysis.log", help="Output file for logging timing results (default: timing_analysis.log).")
    parser.add_argument("--dependency_check", action="store_true", help="Check if dependencies (bandit, flake8, pylint, pyre-check) are installed.")
    return parser

def check_dependencies():
    """
    Checks if required dependencies are installed.

    Returns:
        bool: True if all dependencies are installed, False otherwise.
    """
    # Probed only because the flag exists. The timing run never
    # invokes any of these, so a missing one says nothing about
    # whether an analysis can run.
    dependencies = ["bandit", "flake8", "pylint", "pyre-check"]
    missing_dependencies = []
    for dep in dependencies:
        try:
            subprocess.run([dep, "--version"], check=True, capture_output=True)
        except FileNotFoundError:
            missing_dependencies.append(dep)
        except subprocess.CalledProcessError:
            # Some tools may not have a --version flag that returns cleanly.  Try importing.
            try:
                __import__(dep)
            except ImportError:
                missing_dependencies.append(dep)
    
    if missing_dependencies:
        logging.error(f"Missing dependencies: {', '.join(missing_dependencies)}")
        return False
    return True

def instrument_code(filename):
  """
  Instruments the code with timing measurements.

  Each function body is wrapped so a start stamp is taken on entry
  and the elapsed time is printed from a finally block. The finally
  matters: a plain append at the end of the body never runs for a
  function that returns early, which is most functions worth timing.

  Args:
    filename (str): The name of the Python file to instrument.

  Returns:
    str: The path to the instrumented code, or None on error.
  """
  try:
    with open(filename, "r") as f:
      code = f.read()
  except FileNotFoundError:
    logging.error(f"File not found: {filename}")
    return None
  except Exception as e:
    logging.error(f"Error reading file: {e}")
    return None

  try:
    tree = ast.parse(code)
  except SyntaxError as e:
    # A target that does not parse cannot be instrumented. Returning
    # None lets main exit 1 with this message instead of a traceback.
    logging.error(f"Cannot parse {filename}: {e}")
    return None

  def time_call():
      # time.time(), spelled as an attribute call. The first version
      # built a call to the bare name time, which is the module, so
      # every instrumented function died with "module object is not
      # callable" before its own body ran.
      return ast.Call(func=ast.Attribute(value=ast.Name(id='time', ctx=ast.Load()), attr='time', ctx=ast.Load()), args=[], keywords=[])

  class TimingVisitor(ast.NodeTransformer):
      def visit_FunctionDef(self, node):
          self.generic_visit(node)
          # Underscore names: a target that already uses start_time
          # or duration for its own logic must not be overwritten.
          start = ast.Assign(targets=[ast.Name(id='_sg_start', ctx=ast.Store())], value=time_call())
          report = [
              ast.Assign(targets=[ast.Name(id='_sg_duration', ctx=ast.Store())],
                         value=ast.BinOp(left=time_call(), op=ast.Sub(), right=ast.Name(id='_sg_start', ctx=ast.Load()))),
              ast.Expr(value=ast.Call(func=ast.Name(id='print', ctx=ast.Load()),
                                      args=[ast.Constant(value=f"Function {node.name} took: "), ast.Name(id='_sg_duration', ctx=ast.Load())],
                                      keywords=[])),
          ]
          body = node.body
          prefix = []
          # A docstring has to stay first or it stops being one.
          if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
              prefix, body = body[:1], body[1:]
          node.body = prefix + [start, ast.Try(body=body, handlers=[], orelse=[], finalbody=report)]
          return node

  instrumented_tree = TimingVisitor().visit(tree)
  ast.fix_missing_locations(instrumented_tree)
  instrumented_code = ast.unparse(instrumented_tree)

  instrumented_filename = f"{os.path.splitext(filename)[0]}_instrumented.py"
  try:
      with open(instrumented_filename, "w") as f:
          f.write("import time\n")
          f.write(instrumented_code)
      logging.info(f"Instrumented code written to {instrumented_filename}")
      return instrumented_filename
  except Exception as e:
      logging.error(f"Error writing instrumented code: {e}")
      return None

def run_analysis(instrumented_file, iterations, threshold, output_file):
    """
    Runs the timing analysis on the instrumented code.

    The output file collects whatever the instrumented program
    prints, per iteration. The threshold argument is accepted and
    validated by main, but no verdict is computed from it: nothing
    here compares timings against it, and the log must not pretend
    otherwise.

    Returns:
        int: How many iterations exited non-zero.
    """

    if not os.path.exists(instrumented_file):
        logging.error(f"Instrumented file not found: {instrumented_file}")
        return iterations

    failed = 0
    try:
        with open(output_file, "w") as outfile:
            for i in range(iterations):
                logging.info(f"Running iteration {i+1}/{iterations}")
                # No capture_output here: combining it with an
                # explicit stdout raises ValueError, which the old
                # call hit on every iteration and then reported as
                # an execution error, leaving an empty output file
                # and a success exit.
                result = subprocess.run([sys.executable, instrumented_file], stdout=outfile, stderr=subprocess.PIPE, text=True, check=False)
                if result.returncode != 0:
                    failed += 1
                    logging.error(f"Instrumented run exited {result.returncode}: {result.stderr.strip()}")
        logging.info(f"Analysis completed.  Results written to {output_file}")
    except Exception as e:
        logging.error(f"Error writing to output file: {e}")
        return iterations
    logging.info(f"Failed iterations: {failed} of {iterations}")
    return failed


def main():
    """
    Main function to orchestrate the timing attack analysis.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    # Input validation
    if not os.path.exists(args.target_file):
        logging.error(f"Target file not found: {args.target_file}")
        sys.exit(1)

    if args.iterations <= 0:
        logging.error("Number of iterations must be greater than 0.")
        sys.exit(1)

    if not 0 <= args.threshold <= 1:
        logging.error("Threshold must be between 0 and 1.")
        sys.exit(1)

    if args.dependency_check:
        if not check_dependencies():
            sys.exit(1)

    logging.info(f"Starting timing attack analysis on {args.target_file}...")
    logging.info(f"Number of iterations: {args.iterations}")
    logging.info(f"Threshold: {args.threshold}")
    logging.info(f"Output file: {args.output}")

    # Instrument the code
    instrumented_file = instrument_code(args.target_file)
    if not instrumented_file:
        logging.error("Failed to instrument code. Exiting.")
        sys.exit(1)

    # Run the analysis
    failed = run_analysis(instrumented_file, args.iterations, args.threshold, args.output)

    if failed:
        # Iterations whose instrumented run exited non-zero did not
        # produce timings. Reporting the run as completed at exit 0
        # would hide that the target never ran successfully.
        logging.error(f"Timing attack analysis failed: {failed} of {args.iterations} iterations failed.")
        sys.exit(1)

    logging.info("Timing attack analysis completed.")

if __name__ == "__main__":
    main()