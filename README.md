##Check Point Policy and Object Export
#Supported Policy and Object:
- Nat Rule
- Access Rule, including inline Policy
- Application Site

#Syntax
usage: checkpointexport.py [-h] [-w] (-f  | -r ) (-n | -a | -as)

Check Point Policy Management

optional arguments:
  -h, --help                show this help message and exit
  -w , --writefile          File to write output to
  -f , --file               File contains rule list
  -r , --rule               Rule list, dash or comma separted, no space
  -n, --nat                 nat policy
  -a, --access              security access
  -as, --applicationsite    applicaiton site

#Example:
- python3 checkpointexport.py -a -r 10,100: get access rule 10 and 100, show to screen
- python3 checkpointexport.py -a -r 10-100: get access rule 10 to 100, show to screen
- python3 checkpointexport.py -a -r 10-100 -w accessrule10to100.csv: get access rule 10 to 100, save to accessrule10to100.csv file
- python3 checkpointexport.py -n -f rule.txt: get nat rule list in rule.txt file, show to screen

#Format of rule file if using -f:
1
2,10
40-50
- For Application site, name of application site is used and only , can be used to list multiple names



