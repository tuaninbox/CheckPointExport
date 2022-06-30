# Check Point Firewall Policy and Object Manager
## Demo
![Demo](./Check Point Policy Manager.gif)
![Demo](https://github.com/tuaninbox/CheckPointExport/blob/master/Check%20Point%20Policy%20Manager.gif?raw=true)

## Supported Policies and Objects:
- Nat Rule queried by rule number
- Access Rule, including inline Policy, queried by rule number of main rules, inline policy will be queried automatically. This can be used to query inline policy directly by using its inline policy name
- Application Site queried by name
- Network Group queried by name

## Syntax
usage: cppm.py [-h] [-w] (-f  | -r ) (-n | -s | -a | -as | -g | -ds | -da | -es | -ea | -t)
<br>
Check Point Policy Management
<br>
optional arguments:<br>
  -h, --help                 show this help message and exit<br>
  -w , --writefile           File to write output to<br>
  -f , --file                File contains rule list<br>
  -r , --rule                Rule list, dash or comma separted, no space<br>
  -n, --nat                  NAT Policy<br>
  -s, --security             Access Security<br>
  -a, --application          Access Application<br>
  -as, --applicationsite     Applicaiton Site<br>
  -g, --group                Network Group<br>
  -ds, --disablesecurity     Disable Security Rule<br>
  -da, --disableapplication  Disable Application Rule<br>
  -es, --enablesecurity      Enable Security Rule<br>
  -ea, --enableapplication   Enable Application Rule<br>
  -t, --test                 For Testing Purpose<br>


## Example:
- python3 cppm.py -a -r 10,100: get access rule 10 and 100, show to screen
- python3 cppm.py -a -r 10-100: get access rule 10 to 100, show to screen
- python3 cppm.py -a -r 10-100 -w accessrule10to100.csv: get access rule 10 to 100, save to accessrule10to100.csv file
- python3 cppm.py -n -f rule.txt: get nat rule list in rule.txt file, show to screen
- python3 cppm.py -as -r Blocked_Sites: get application site list with name Blocked_Sites, show to screen

## Format of rule file if using -f: number

1  
2,10  
40-50  
60

- For number items, numbers which are usually rule, list of rules separated by comma (,) and range of rules separated by dash (-), no space between numbers, comma or dash

## Format of rule file if using -f: name  

Allowed_Sites,Block_Sites  
Web_Servers  

- For name items, list of names can be separated by comma (,) without space before or after. 



