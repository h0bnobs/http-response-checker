# HTTP response checker that looks for secure headers and cookie attributes
Makes a request to a url and checks the response against a [list of security headers](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html).<br>It then gets the cookies that the page uses. 
## Usage
```
git clone https://github.com/h0bnobs/security-response-checker
cd security-response-checker
pip install -r requirements.txt
python security-response-checker
```
## Examples
Print the headers and cookie data of one url:
```
python security-response-checker -u https://google.com
```
Print the headers and cookie data of multiple urls in a txt file and output them in a readable format a file:
```
python security-response-checker -i target_urls.txt -o output_file.txt
```
Print nothing to the terminal but send the output to a file:
```
python security-repsponse-checker -i target_urls.txt -q -o output_file.txt
```

## Information
There are 3 types of input files accepted: [dirb's](https://www.kali.org/tools/dirb/) output file, [ffuf's](https://github.com/ffuf/ffuf) output file and a simple txt file, with each row containing a URL. 
