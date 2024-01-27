# sha256 
Implementation of the sha256 algorithm testing and using chatgpt in its development

# Verification tests 
For testing and making sure the algorithm  worked, I used the default installed `sha256sum` program on ubuntu  against some arbitrary data
to confirm I had the same result for the program.
```
sha256sum arbitrary.txt
54aa2300c752640be131e6b6c9d73f9eb23f8142db743e4f997447eb6747d043  arbitrary.txt

./sha256 -f arbitrary.txt
54aa2300c752640be131e6b6c9d73f9eb23f8142db743e4f997447eb6747d043  arbitrary.txt
```

# Usage
```
Usage: sha256
Given a file of data, return the sha256 hash over it

-f      File of data to hash with sha256
```
