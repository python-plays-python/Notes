#python3
import sys
text = " ".join(sys.argv[1:])
print("input: ", text)

small = "abcdefghijklmnopqrstuvwxyz"
large = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

mod_text = ""
for i in text:
	if (i in small):
		mod_text += small[(ord(i)-97+ 13)%len(small)]
		
	elif (i in large):
		mod_text += large[(ord(i)-65 +13)%len(large)]
	else:
		mod_text += i

print(mod_text)
	