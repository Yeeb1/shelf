# Tools

## namegen.py

This tool generates various username variants based on a list of input names. It is especially useful for creating permutations of usernames that can be used during penetration testing. The tool supports generating combinations for both single-word and multi-word names, producing multiple formats such as hyphenated, underscored, and concatenated usernames.

#### Features:
- Generates multiple variants for both single-word and multi-word names.
- Supports variants with hyphens, underscores, dots, and concatenation.
- Saves generated usernames to a `users.generated` file in the current directory.

#### Example:
```bash
┌──(kalikali)-[/tmp/foo]
└─$ echo "Foo Bar" > names.txt 
                                                                                                                                                           
┌──(kalikali)-[/tmp/foo]
└─$ namegen.py names.txt
[*] Names Loaded:
    + Foo Bar
[*] File Saved to: /tmp/foo/users.generated
   
┌──(kalikali)-[/tmp/foo]
└─$ cat users.generated 
Foo-Bar
Foo_Bar
Foo.Bar
Foo Bar
FooBar
FBar
FooB
F-Bar
F_Bar
F.Bar
Foo-B
Foo_B
Foo.B
FB
```


## CertipyPermParse.py

This tool parses Certipy JSON output to identify anomalies in Access Control Lists (ACLs), helping you hunt for potential targets in a Windows Active Directory environment. By analyzing certificate templates, permissions, and vulnerabilities, the tool filters out standard groups and highlights unusual access permissions that could indicate misconfigurations or attack vectors.

#### Features:
- Parses JSON output from Certipy to identify anomalies in ACLs.
- Filters out known administrative groups such as "Domain Admins" and "Enterprise Admins" to focus on unusual principals.
- Detects potential certificate vulnerabilities and permissions issues, such as unauthorized write access.
- Supports exporting results to CSV for easy analysis.
- Option to check only active certificates.
- Allows for additional exclusions of specific principals.

#### Usage:
```bash
python3 certipy_parser.py <file_path> [--csv <output_file>] [--exclude <principal1> <principal2>] [--active-only]
```

- *<file_path>*: Path to the Certipy JSON output file.
- --*csv*: (Optional) Path to save the parsed results as a CSV file.
- --*exclude*: (Optional) Additional principals to exclude from the results.
- *--active-only*: (Optional) Check only active certificate templates.

```bash
python3 certipy_parser.py certipy_output.json --csv results.csv --exclude "Test User" --active-only
```
