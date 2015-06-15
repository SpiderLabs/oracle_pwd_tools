# oracle_pwd_tools
#Oracle Database Password Tools
Oracle Database 12c password cracking script (Python) which uses data from a successful authentication network capture.
Variables under "# Server authentication" and "# Client authentication" should be set to data from your capture.
Also the passwords list should be initialized with your password dictionary entries.

Note that this script will only work for the '12a' protocol version which is the latest as of Oracle Database 12.1.0.2.