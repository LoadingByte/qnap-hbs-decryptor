# QNAP HBS Decryptor

This small CLI program efficiently decrypts files, directory trees, or a stream from stdin
encrypted client-side by QNAP's Hybrid Backup Sync (HBS) app.

The program requires the `libcrypto` library (which is provided by OpenSSL) to be installed on your system.
Also, please be aware that at the moment, the source code only compiles on Unix-like systems,
but adapting it to Windows should not be too hard.
If you do manage to build it on Windows, feel free to submit a pull request!

## Compilation & Usage

To compile this program, run:

    $ make

Then, you may run

    $ ./qnap-hbs-decryptor -h

to print out the following help page on how to use the program:

    Usage: ./qnap-hbs-decryptor [-p <pw>] [-m <mem>] [-t <tmp>] [-v] [file/dir...]

    Options:
      -p <password>    The password you have set when creating the HBS backup job.
                         Omitting this option will lead to an interactive password
                         prompt.
      -m <memory>      Maximum amount of megabytes in RAM which may be consumed
                         for buffering a decrypted file. Decrypting files larger
                         than this limit needs a temporary file. Default is 512.
      -t <temp file>   Path to a file which may be (over)written with arbitrary
                         temporary data. It may become as big as the largest
                         decrypted file. Omitting this option will ask the OS for
                         a temporary file, which might not fit enough data if your
                         decrypted files weigh multiple GB, leading to IO errors.
      -v               Enable verbose output. Prints every successfully
                         decrypted file and every non-HBS file to stdout, while
                         errors are still printed to stderr. Only effective
                         when not reading from stdin.

    When providing files and/or directories as arguments, these files will be
    decrypted in-place. Caution! That means that their contents will be
    overwritten, but their file attributes are preserved.

    If no files or directories are provided, the program expects an encrypted file
    on stdin and writes the decrypted file to stdout.
