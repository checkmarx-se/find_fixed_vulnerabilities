## About

This script is not supported by Checkmarx and edge cases are not tested, use it as your own.

This python3 script takes two Checkmarx XML report files as arguments (the first argument needs to be the earlier report and the second argument needs to be the latest report) to find vulnerabilities that were fixed.

## Execute

Run command:
```
python cx-scan_find_fixed.py report2.xml report1.xml
```

## Output

It will create a CSV file in the same directory named fixed_vulnerabilties.csv
