# Check Point Policy and Object Export
## Supported Policy and Object:
- Nat Rule queried by rule number
- Access Rule, including inline Policy, queried by rule number of main rules, inline policy will be queried automatically. This can be used to query just inline policy directly by using its inline policy name
- Application Site queried by name
- Network Group queried by name

## Syntax
usage: checkpointexport.py [-h] [-w] (-f  | -r ) (-n | -a | -as | -g)

Check Point Policy Management

optional arguments:
  -h, --help                show this help message and exit
  -w , --writefile          File to write output to
  -f , --file               File contains rule list
  -r , --rule               Rule list, dash or comma separted, no space
  -n, --nat                 nat policy
  -a, --access              security access
  -as, --applicationsite    applicaiton site
  -g, --group               network group

## Example:
- python3 checkpointexport.py -a -r 10,100: get access rule 10 and 100, show to screen
- python3 checkpointexport.py -a -r 10-100: get access rule 10 to 100, show to screen
- python3 checkpointexport.py -a -r 10-100 -w accessrule10to100.csv: get access rule 10 to 100, save to accessrule10to100.csv file
- python3 checkpointexport.py -n -f rule.txt: get nat rule list in rule.txt file, show to screen
- python3 checkpointexport.py -as -r Blocked_Sites: get application site list with name Blocked_Sites, show to screen

## Format of rule file if using -f: number

1  
2,10  
40-50  
60

## Format of rule file if using -f: name  

Allowed_Sites,Block_Sites  
Web_Servers  

- For number items, numbers which are usually rule, list of rules separated by comma (,) and range of rules separated by dash (-), no space between numbers, comma or dash
- For name items, list of names can be separated by comma (,) without space before or after. 



