#!/usr/bin/env python
#-*- coding: utf-8 -*-

'''
Hash Enc-Dnc - Tools Termux
This project was created by Dfv47 with Black Coder Crush. 
Copyright 02 - 06 - 2k19 @m_d4fv
Thanks to @ciku370
'''

try:
        import os,sys,hashlib,random,binascii,urllib,re,passlib
except Exception as F:
        exit("[ModuleErr] %s"%(F))

if sys.version[0] in '3':
        exit("[sorry] use python version 2")

from urllib import urlopen, urlencode
from re import search
# color
A = "\033[1;30m"  #Grey
B = "\033[1;34m"  #Blue
Y = "\033[1;33m"  #Yellow
G = "\033[1;32m"  #Green
W = "\033[1;37m"  #White
R = "\033[31;1m"  #Red
C = "\033[1;36m"  #Cyan
N = "\033[0;00m"  #Normal 
# Random color
rand = (B,Y,G,W,R,C)
P = random.choice(rand)

import hashlib
import os,time
	
try:
        import os,sys,readline,rlcompleter,random,progressbar
except Exception as F:
        exit("[ModuleErr] %s"%(F))

if sys.version[0] in '3':
        exit("[sorry] use python version 2")

def hash():
    os.system('clear')
    banner()
    
def banner():
	print R+'\n             Hash EncDnc Tools'+W+' v.1.0'
	print W+'  ------------------------------------------------'
	print P+'     88  88    db    .dP"Y8 88  88 88888 88""Yb '
	print P+'     88  88   dPYb   `Ybo." 88  88 88__  88__dP '
	print P+'     888888  dP__Yb  o.`Y8b 888888 88""  88"Yb  '
	print P+'     88  88 dP""""Yb 8bodP  88  88 88888 88  Yb '
	print W+'  ------------------------------------------------'
	print "\033[2;2m   python2 "+sys.argv[0]+" -enc   python2 "+sys.argv[0]+" -info"
	print "\033[2;2m   python2 "+sys.argv[0]+" -dnc   python2 "+sys.argv[0]+" -update"+N

def awal(): 
    print R+'\n             Hash EncDnc Tools'+W+' v.1.0'
    print W+'  ------------------------------------------------'
    print P+'     88  88    db    .dP"Y8 88  88 88888 88""Yb '
    print P+'     88  88   dPYb   `Ybo." 88  88 88__  88__dP '
    print P+'     888888  dP__Yb  o.`Y8b 888888 88""  88"Yb  '
    print P+'     88  88 dP""""Yb 8bodP  88  88 88888 88  Yb '
    print W+'  ------------------------------------------------'

def update():
    os.system ('clear') 
    awal()
    print (W+"["+B+"+"+W+"] UPDATE WORDLIST")
    time.sleep(1)
    print (W+"["+B+"+"+W+"] Remove old wordlist")
    os.system("rm -rf wordlist.txt")
    time.sleep(1)
    print (W+"["+B+"+"+W+"] Downloading new wordlist")
    time.sleep(1) 
    print (W+"["+B+"+"+W+"] Curl Started ...\n"+W)
    os.system("curl https://raw.githubusercontent.com/md4fv/hashencdnc/master/wordlist.txt -o wordlist.txt")
    print (W+"["+B+"+"+W+"] Download Finish\n"+W)
    sys.exit()
		
def info(): 
    os.system ('clear') 
    awal() 
    print B+"\n ========================"+W+" INFO "+B+"========================="
    print B+" | "+W+"Name     "+C+":"+W+" HashEnc-Dnc v.1.0"+B+"                        |"
    print B+" | "+W+"Author   "+C+":"+W+" Dfv47"+R+"@"+W+"Mfth'DaffaHasani"+B+"                   |"
    print B+" | "+W+"Github   "+C+":"+W+" https://github.com/md4fv"+B+"                 |"
    print B+" | "+W+"Date     "+C+":"+W+" 02 - 06 - 2019"+B+"                           |"
    print B+" | "+W+"Team     "+C+":"+W+" Black Coder Crush"+B+"                        |"
    print B+" | "+W+"Thanks   "+C+":"+W+" https://github.com/ciku370"+B+"               |"   
    print B+" =======================================================\n"
    print W+"["+B+"+"+W+"] python2 "+sys.argv[0]+" --enc    "+B+":"+W+" Encryption hash    "
    print W+"["+B+"+"+W+"] python2 "+sys.argv[0]+" --dnc    "+B+":"+W+" Dencryption hash      "
    print W+"["+B+"+"+W+"] python2 "+sys.argv[0]+" --update "+B+":"+W+" Update HashEncDn Tools"
    print W+"["+B+"+"+W+"] python2 "+sys.argv[0]+" --info   "+B+":"+W+" Info about HashEncDnc Tools"  
		
#Moduls tambahan
#pip install scrypt
import hashlib,os,time
from passlib.hash import pbkdf2_sha1,pbkdf2_sha256,pbkdf2_sha512
from passlib.hash import sha256_crypt,sha512_crypt,md5_crypt,sha1_crypt
from passlib.hash import sun_md5_crypt,des_crypt,bsdi_crypt,bigcrypt,crypt16 #✓
from passlib.hash import phpass,scram,scrypt,apr_md5_crypt,cta_pbkdf2_sha1 #✓
from passlib.hash import dlitz_pbkdf2_sha1,ldap_md5_crypt,ldap_hex_md5,ldap_hex_sha1 #✓
from passlib.hash import ldap_pbkdf2_sha1,ldap_pbkdf2_sha256,ldap_pbkdf2_sha512 #4
from passlib.hash import atlassian_pbkdf2_sha1,fshp,mysql323,mysql41,postgres_md5 #5✓
from passlib.hash import oracle10,oracle11,lmhash,nthash,msdcc,msdcc2,cisco_type7 #6✓
from passlib.hash import grub_pbkdf2_sha512,hex_sha1 #✓
from passlib import pwd 
from passlib.hash import mssql2005 as cuk
from passlib.hash import mssql2000 as cak
from passlib.hash import ldap_salted_md5 as cik
from passlib.hash import cisco_type7 as m25
#Hash encryption
def enc():
    awal() 
    putih = "\033[97m"
    dfv = raw_input(W+"["+B+"+"+W+"] Your Text     "+B+": "+G)
    asw = raw_input(W+"["+B+"+"+W+"] Your Password "+B+": "+G)
    print W+"\n* Generate Hash . . . . Please Wait !!!"
    time.sleep(1) 
    print (W+'  ------------------------------------------------')   
    #md5
    daf1 = hashlib.md5(dfv.encode("utf -8")).hexdigest()
    print W+"["+B+"+"+W+"] Md5    "+B+":"+W,daf1
    time.sleep(0.1)
    #sha256
    daf2 = hashlib.sha256(dfv.encode()).hexdigest()
    print W+"["+B+"+"+W+"] Sha256 "+B+":"+W,daf2
    time.sleep(0.1) 
    #sha224
    daf4 = hashlib.sha224(dfv.encode()).hexdigest()
    print W+"["+B+"+"+W+"] Sha224 "+B+":"+W,daf4
    time.sleep(0.1)
    #sha512
    daf5 = hashlib.sha512(dfv.encode()).hexdigest()
    print W+"["+B+"+"+W+"] Sha512 "+B+":"+W,daf5
    time.sleep(0.1)    
    #sha384
    daf6 = hashlib.sha384(dfv.encode()).hexdigest()
    print W+"["+B+"+"+W+"] Sha384 "+B+":"+W,daf6
    time.sleep(0.1)
    #sha1
    daf11 = hashlib.sha1(dfv.encode()).hexdigest()
    print W+"["+B+"+"+W+"] Sha1   "+B+":"+W,daf11
    time.sleep(0.1)
    #pbkdf2_sha1
    daf12 = pbkdf2_sha1.hash(dfv)
    print W+"["+B+"+"+W+"] Pbkdf2_sha1   "+B+":"+W,daf12
    time.sleep(0.1)
    #pbkdf2_sha256
    daf13 = pbkdf2_sha256.hash(dfv)
    print W+"["+B+"+"+W+"] Pbkdf2_sha256 "+B+":"+W,daf13
    time.sleep(0.1)
    #pbkdf2_sha512 
    daf14 = pbkdf2_sha512.hash(dfv)
    print W+"["+B+"+"+W+"] Pbkdf2_sha512 "+B+":"+W,daf14
    time.sleep(0.1)
    #sha256_crypt
    daf15 = sha256_crypt.hash(dfv)
    print W+"["+B+"+"+W+"] Sha256_crypt  "+B+":"+W,daf15
    time.sleep(0.1)
    #sha512_crypt
    daf16 = sha512_crypt.hash(dfv)
    print W+"["+B+"+"+W+"] Sha512_crypt  "+B+":"+W,daf16
    time.sleep(0.1)
    #md5_crypt
    daf17 = md5_crypt.hash(dfv)
    print W+"["+B+"+"+W+"] Md5_crypt  "+B+":"+W,daf17
    time.sleep(0.1)
    #sha1_crypt
    daf18 = sha1_crypt.hash(dfv)
    print W+"["+B+"+"+W+"] Sha_crypt  "+B+":"+W,daf18
    time.sleep(0.1)
    #sha1_crypt
    daf18 = sha1_crypt.hash(dfv)
    print W+"["+B+"+"+W+"] Sha_crypt  "+B+":"+W,daf18
    time.sleep(0.1)
    #sun_md5_crypt
    daf19 = sun_md5_crypt.hash(dfv)
    print W+"["+B+"+"+W+"] Sun_md5_crypt "+B+":"+W,daf19
    time.sleep(0)
    #des_crypt
    daf20 = des_crypt.hash(dfv)
    print W+"["+B+"+"+W+"] Des_crypt  "+B+":"+W,daf20
    time.sleep(0.1)
    #bsdi_crypt
    daf21 = bsdi_crypt.hash(dfv)
    print W+"["+B+"+"+W+"] Bsdi_crypt "+B+":"+W,daf21
    time.sleep(0.1)
    #bigcrypt
    daf22 = bigcrypt.hash(dfv)
    print W+"["+B+"+"+W+"] Bigcrypt   "+B+":"+W,daf22
    time.sleep(0.1)
    #crypt16
    daf23 = crypt16.hash(dfv)
    print W+"["+B+"+"+W+"] Crypt16 "+B+":"+W,daf23
    time.sleep(0.1)
    #phpass
    daf24 = phpass.hash(dfv)
    print W+"["+B+"+"+W+"] Phpass  "+B+":"+W,daf24
    time.sleep(0.1)
    #scram
    daf25 = scram.hash(dfv)
    print W+"["+B+"+"+W+"] Scram   "+B+":"+W,daf25
    time.sleep(0.1)
    #apr_md5_crypt
    daf27 = apr_md5_crypt.hash(dfv)
    print W+"["+B+"+"+W+"] Apr_Md5_Crypt    "+B+":"+W,daf27
    time.sleep(0.1)
    #cta_pbkdf2
    daf28 = cta_pbkdf2_sha1.hash(dfv)
    print W+"["+B+"+"+W+"] Cta_pbkdf2_sha1  "+B+":"+W,daf28
    time.sleep(0.1)
    #dlitz_pbdf2_sha1
    daf29 = dlitz_pbkdf2_sha1.hash(dfv)
    print W+"["+B+"+"+W+"] Dlitz_pbkdf_sha1 "+B+":"+W,daf29
    time.sleep(0.1)
    #ldap_md5_crypt
    daf30 = ldap_md5_crypt.hash(dfv)
    print W+"["+B+"+"+W+"] Ldap_Md5_Crypt   "+B+":"+W,daf30
    time.sleep(0.1)
    #ldap_hex_md5
    daf31 = ldap_hex_md5.hash(dfv)
    print W+"["+B+"+"+W+"] Ldap_Hex_Md5   "+B+":"+W,daf31
    time.sleep(0.1)
    #ldao_hex_sha1
    daf32 = ldap_hex_sha1.hash(dfv)
    print W+"["+B+"+"+W+"] Ldap_Hex_Sha1  "+B+":"+W,daf32
    time.sleep(0.1)
    #ldap_pbkdf2_sha1
    daf33 = ldap_pbkdf2_sha1.hash(dfv)
    print W+"["+B+"+"+W+"] Ldap_pbkdf2_sha1  "+B+":"+W,daf33
    time.sleep(0.1)
    #ldap_pbkdf2_sha256
    daf34 = ldap_pbkdf2_sha256.hash(dfv)
    print W+"["+B+"+"+W+"] Ldap_pbkdf2_sha256  "+B+":"+W,daf34
    time.sleep(0.1)
    #ldap_pbkdf2_sha512
    daf35 = ldap_pbkdf2_sha512.hash(dfv)
    print W+"["+B+"+"+W+"] Ldap_pbdf2_sha512   "+B+":"+W,daf35
    time.sleep(0.1)
    #atlassian_pbkdf2_sha1
    daf36 = atlassian_pbkdf2_sha1.hash(dfv)
    print W+"["+B+"+"+W+"] Atlassian_pbkdf2_sha1  "+B+":"+W,daf36
    time.sleep(0.1)
    #fshp
    daf37 = fshp.hash(dfv)
    print W+"["+B+"+"+W+"] Fshp  "+B+":"+W,daf37
    time.sleep(0.1)
    #mysql323
    daf38 = mysql323.hash(dfv)
    print W+"["+B+"+"+W+"] Mysql323 "+B+":"+W,daf38
    time.sleep(0.1)
    #mysql41
    daf39 = mysql41.hash(dfv)
    print W+"["+B+"+"+W+"] Mysql41  "+B+":"+W,daf39
    time.sleep(0.1)
    #postgres_md5
    daf40 = postgres_md5.hash(dfv,user=asw)
    print W+"["+B+"+"+W+"] Postgres_md5 "+B+":"+W,daf40
    time.sleep(0.1)
    #oracle10
    daf41 = oracle10.hash(dfv,user=asw)
    print W+"["+B+"+"+W+"] Oracle10 "+B+":"+W,daf41
    time.sleep(0.1)
    #oracle11
    daf42 = oracle11.hash(dfv)
    print W+"["+B+"+"+W+"] Oracle11 "+B+":"+W,daf42
    time.sleep(0.1)
    #lmhash
    daf43 = lmhash.hash(dfv)
    print W+"["+B+"+"+W+"] Lmhash  "+B+":"+W,daf43
    time.sleep(0.1)
    #nthash
    daf44 = nthash.hash(dfv)
    print W+"["+B+"+"+W+"] Nthash  "+B+":"+W,daf44
    time.sleep(0.1)
    #msdcc
    daf45 = msdcc.hash(dfv,user=asw)
    print W+"["+B+"+"+W+"] Msdcc   "+B+":"+W,daf45
    time.sleep(0.1)
    #msdcc2
    daf46 = msdcc2.hash(dfv,user=asw)
    print W+"["+B+"+"+W+"] Msdcc2  "+B+":"+W,daf46
    time.sleep(0.1)
    #cisco_type7
    daf47 = cisco_type7.hash(dfv)
    print W+"["+B+"+"+W+"] Cisco_type7  "+B+":"+W,daf47
    time.sleep(0.1)
    #grub_pbkdf2_sha512
    daf48 = grub_pbkdf2_sha512.hash(dfv)
    print W+"["+B+"+"+W+"] Grub_pbkdf2_sha512  "+B+":"+W,daf48
    time.sleep(0.1)
    #hex_sha1
    daf49 = hex_sha1.hash(dfv)
    print W+"["+B+"+"+W+"] Hex_Sha1   "+B+":"+W,daf49
    time.sleep(0.1)
    #pwd
    daf50 = pwd.genword()
    print W+"["+B+"+"+W+"] Pwd  "+B+":"+W,daf50
    time.sleep(0.1)
    #mssql2005
    daf51 = cuk.hash(dfv)
    print W+"["+B+"+"+W+"] Mssql2005  "+B+":"+W,daf51
    time.sleep(0.1)
    #Mssql2000
    daf52 = cak.hash(dfv)
    print W+"["+B+"+"+W+"] Mssql2000  "+B+":"+W,daf52
    time.sleep(0.1)
    #ldap_salted_md5
    daf52 = cik.hash(dfv)
    print W+"["+B+"+"+W+"] Ldap_salted_md5  "+B+":"+W,daf52
    time.sleep(0.1)    

#Mmodule tambahan
import progressbar
from passlib.hash import mysql323 as m20
from passlib.hash import mysql41 as m25
from passlib.hash import mssql2000 as ms20
from passlib.hash import mssql2005 as ms25
from passlib.hash import nthash as nthash
from passlib.hash import lmhash as lmhash
def ulang():
    raw_input(Y+"\n  ["+R+"?"+Y+"] Press enter to menu ...")
    os.system('clear')
    dnc()
#Hash dencryption
def dnc():
	awal()
	hash_str = raw_input(W+"  ["+G+"?"+W+"] Hash "+G+":"+W+" ")
	print (W+"  ["+G+"*"+W+"] Hash type ...")
	time.sleep(2)	
	# Contoh Hash nya , nb : jangan di ubah ntar error
	SHA512= ('dd0ada8693250b31d9f44f3ec2d4a106003a6ce67eaa92e384b356d1b4ef6d66a818d47c1f3a2c6e8a9a9b9bdbd28d485e06161ccd0f528c8bbb5541c3fef36f')
	md = ('ae11fd697ec92c7c98de3fac23aba525')
	sha1 = ('4a1d4dbc1e193ec3ab2e9213876ceb8f4db72333')
	sha224 = ('e301f414993d5ec2bd1d780688d37fe41512f8b57f6923d054ef8e59')
	sha384 = ('3b21c44f8d830fa55ee9328a7713c6aad548fe6d7a4a438723a0da67c48c485220081a2fbc3e8c17fd9bd65f8d4b4e6b')
	sha256 = ('2c740d20dab7f14ec30510a11f8fd78b82bc3a711abe8a993acdb323e78e6d5e')
	mysql1323 = ("5d2e19393cc5ef67")
	mysql41 = ("*88166B019A3144C579AC4A7131BCC3AD6FF61DA6")
	mssql2000 = ("0x0100DE9B3306258B37432CAC3A6FB7C638946FA393E09C9CBC0FA8C6E03B803390B1C3E7FB112A21B2304595D490")
	mssql2005 = ('0x01008110620C7BD03A38A28A3D1D032059AE9F2F94F3B74397F8')
	#mysql_hash
	if len(hash_str)==len(mysql1323) and hash_str.isdigit()==False and hash_str.isalpha()==False and hash_str.isalnum()==True:
		print (W+"\n  ["+G+"#"+W+"] Hash type "+G+": "+W+"mysql 3.2.3")
		hash = "mysql1323"
	#mysql141
	elif len(hash_str)==len(mysql41) and "*" in hash_str:
		print (W+"\n  ["+G+"#"+W+"] Hash type "+G+": "+W+"mysql 4.1")
		hash = "mysql41"
	#mssql2000
	elif len(hash_str)==len(mssql2000) and "0x0" in hash_str:
		print (W+"\n  ["+G+"#"+W+"] Hash type "+G+": "+W+"mssql2000")
		hash = "mssql2000"
	#mssql2005
	elif len(hash_str)==len(mssql2005) and "0x0" in hash_str:
		print (W+"\n  ["+G+"#"+W+"] Hash type "+G+": "+W+"mssql2005")
                hash = "mssql2005"
	elif len(hash_str)==len(SHA512) and hash_str.isdigit()==False and hash_str.isalpha()==False and hash_str.isalnum()==True:
	        print (W+"\n  ["+G+"1"+W+"] sha512")
		print (W+"  ["+G+"2"+W+"] whirlpool")
		cek = raw_input(W+"  ["+G+"?"+W+"] Choose type : ")
		print ""
	#sha512
		if cek == "1" or cek == "01" or cek == "sha512":
			hash = "sha512"
	#whirlpool
		elif cek == "2" or cek == "02" or cek == "whirlpool":
			hash = "whirlpool"
		else:
			print (W+"  ["+R+"!"+W+"] Exiting ... \n")
                        sys.exit()
	elif len(hash_str)==len(md) and hash_str.isdigit()==False and hash_str.isalpha()==False and hash_str.isalnum()==True:
		print (W+"\n  ["+G+"1"+W+"] md4")
		print (W+"  ["+G+"2"+W+"] md5")
		print (W+"  ["+G+"3"+W+"] Nthash")
		print (W+"  ["+G+"4"+W+"] Lmhash")
		print (W+"  ["+G+"5"+W+"] Ntlm hash")
		cek = raw_input(W+"  ["+G+"?"+W+"] Choose type : ")
		print ""
	#md4
		if cek == "1" or cek == "01" or cek == "md4" or cek == "MD4" or cek == "Md4":
			hash = "md4"
	#md5
		elif cek == "2" or cek == "02" or cek == "md5" or cek == "MD5" or cek == "Md5":
			try:
				print (W+"  ["+G+"*"+W+"] Open google")
 				time.sleep(0.3)
				print (W+"  ["+G+"*"+W+"] Starting ...")
				time.sleep(0.3)
				start = ("00:00:00")
				start1 = time.time()
				print (G+"\n  ["+W+"{}"+G+"] "+W+"Searching..."+Y).format(start)
				data = urlencode({"md5":hash_str,"x":"21","y":"8"})
				html = urlopen("http://md5.my-addr.com/md5_decrypt-md5_cracker_online/md5_decoder_tool.php", data)
				find = html.read()
				match = search (r"<span class='middle_title'>Hashed string</span>: [^<]*</div>", find)    
				if match:
				      end = time.strftime("%H:%M:%S", time.gmtime(time.time() - start1))
				      print (G+"  ["+W+"{}"+G+"] "+W+"Stopped...\n").format(end)
				      time.sleep(0.3)
				      print (W+"  ["+G+"+"+W+"] Password found ")
				      print (W+"  ["+G+"+"+W+"] Hash type "+G+": "+W+"md5")
				      print (W+"  ["+G+"+"+W+"] "+(hash_str)+" : "+G+(match.group().split('span')[2][3:-6])+"\n")
				      ulang()
				else:
				      data = urlencode({"md5":hash_str,"x":"21","y":"8"})
				      html = urlopen("http://md5.my-addr.com/md5_decrypt-md5_cracker_online/md5_decoder_tool.php", data)
				      find = html.read()
				      match = search (r"<span class='middle_title'>Hashed string</span>: [^<]*</div>", find)
				      if match:
				            end = time.strftime("%H:%M:%S", time.gmtime(time.time() - start1))
				            print (G+"  ["+W+"{}"+G+"] "+W+"Stopped...").format(end)
				            time.sleep(0.3)
				            print (W+"  ["+G+"+"+W+"] "+hash_str+" : "+G+match.group().split('span')[2][3:-6]+W+" \n")
				            ulang()
				      else:
				            url = "http://www.nitrxgen.net/md5db/" + hash_str
				            cek = urlopen(url).read()
				            if len(cek) > 0:
				                    end = time.strftime("%H:%M:%S", time.gmtime(time.time() - start1))
				                    print (G+"  ["+W+"{}"+G+"] "+W+"Stopped...").format(end)
				                    time.sleep(0.3)
				                    print (W+"  ["+G+"+"+W+"] Password found ")
				                    print (W+"  ["+G+"+"+W+"] "+hash_str+" : "+G+cek+"\n")
				                    ulang()
				            else:
				                    end = time.strftime("%H:%M:%S", time.gmtime(time.time() - start1))
				                    print (G+"  ["+W+"{}"+G+"]"+W+" Password not found\n").format(end)
				                    hash = "md5"
			except IOError:
				end = time.strftime("%H:%M:%S", time.gmtime(time.time() - start1))
				print (G+"  ["+W+"{}"+G+"]"+W+" Timeout\n").format(end)
				hash = "md5"
	#nthash
		elif cek == "03" or cek == "3" or cek.upper() == "NTHASH":
			hash = "nthash"
	#lmhash
		elif cek == "04" or cek == "4" or cek.upper() == "LMHASH":
			hash = "lmhash"
	#ntlm
		elif cek == "05" or cek == "5" or cek.upper() == "NTLM":
			hash = "ntlm"
		else:
			print (W+"  ["+R+"!"+W+"] Input failed !!!"+W)
			ulang() 
	elif len(hash_str)==len(sha1) and hash_str.isdigit()==False and hash_str.isalpha()==False and hash_str.isalnum()==True:
		print (W+"\n  ["+G+"1"+W+"] sha1")
		print (W+"  ["+G+"2"+W+"] ripemd160")
		cek = raw_input(W+"  ["+G+"?"+W+"] Choose type : ")
		print ""
	#sha1
		if cek == "1" or cek == "01" or cek == "sha1" or cek == "SHA1" or cek == "Sha1":
			print (W+"  ["+G+"*"+W+"] Open google")
			time.sleep(0.3)
			print (W+"  ["+G+"*"+W+"] Starting ...")
			time.sleep(0.3)
			start = ("00:00:00")
			start1 = time.time()
			print (G+"\n  ["+W+"{}"+G+"] "+W+"Searching..."+Y).format(start)
			try:
				data = urlencode({"auth":"8272hgt", "hash":hash_str, "string":"","Submit":"Submit"})
				html = urlopen("http://hashcrack.com/index.php" , data)
				find = html.read()
				match = search (r'<span class=hervorheb2>[^<]*</span></div></TD>', find)
 				if match:
					end = time.strftime("%H:%M:%S", time.gmtime(time.time() - start1))
					print (G+"  ["+W+"{}"+G+"] "+W+"Stopped...").format(end)
					time.sleep(0.3)
					print (W+"  ["+G+"+"+W+"] Password found ")
					print (W+"  ["+G+"+"+W+"] Hash type "+G+": "+W+"SHA1")
					print (B+"["+W+"+"+B+"] "+W+hash_str+Y+" 0={==> "+W+match.group().split('hervorheb2>')[1][:-18]+"\n")
					sys.exit()
				else:
					end = time.strftime("%H:%M:%S", time.gmtime(time.time() - start1))
					print (G+"  ["+W+"{}"+G+"]"+W+" Password not found").format(date)
					hash = "sha1"
			except IOError:
				end = time.strftime("%H:%M:%S", time.gmtime(time.time() - start1))
				print (G+"  ["+W+"{}"+G+"]"+W+" Timeout\n").format(end)
				hash = "sha1"
	#ripemd160
		elif cek == "2" or cek == "02" or cek == "ripemd160":
			hash = 'ripemd160'
		else:
		    print (W+"  ["+R+"!"+W+"] Input failed !!!"+W)
		    ulang()
    #sha224
	elif len(hash_str)==len(sha224) and hash_str.isdigit()==False and hash_str.isalpha()==False and hash_str.isalnum()==True:
		print (W+"\n  ["+G+"#"+W+"] Hash type "+G+": "+W+"SHA224")
		hash = "SHA224"
	#sha384
	elif len(hash_str)==len(sha384) and hash_str.isdigit()==False and hash_str.isalpha()==False and hash_str.isalnum()==True:
		print (W+"\n  ["+G+"#"+W+"] Hash type "+G+": "+W+" SHA384")
		hash = "SHA384"
	#sha256
	elif len(hash_str)==len(sha256) and hash_str.isdigit()==False and hash_str.isalpha()==False and hash_str.isalnum()==True:
		print (W+"\n  ["+G+"#"+W+"] Hash type "+G+": "+W+"sha256")
		print (W+"  ["+G+"*"+W+"] Open google")
		time.sleep(0.3)
		print (W+"  ["+G+"*"+W+"] Starting ...")
		time.sleep(0.3)
		start = ("00:00:00")
		start1 = time.time()
		print (B+"\n["+W+"{}"+B+"] "+G+"Searching..."+Y).format(start)
		try:
			data = urlencode({"hash":hash_str, "decrypt":"Decrypt"})
			html = urlopen("http://md5decrypt.net/en/Sha256/", data)
			find = html.read()
			match = search (r'<b>[^<]*</b><br/><br/>', find)
			if match:
			    end = time.strftime("%H:%M:%S", time.gmtime(time.time() - start1))
			    print (G+"  ["+W+"{}"+G+"] "+W+"Stopped...").format(end)
			    time.sleep(0.3)
			    print (W+"  ["+G+"+"+W+"] Password found ")
			    print (W+"  ["+G+"+"+W+"] "+hash_str+Y+" : "+G+match.group().split('<b>')[1][:-14]+"\n")
			    sys.exit()
			else:
			    end = time.strftime("%H:%M:%S", time.gmtime(time.time() - start1))
			    print (G+"  ["+W+"{}"+G+"]"+W+" Password not found\n").format(end)
			    hash = "sha256"
		except IOError:
				end = time.strftime("%H:%M:%S", time.gmtime(time.time() - start1))
				print (W+"  ["+W+"{}"+G+"]"+W+" Timeout\n").format(end)
				hash = "sha256"
	else:
		print (W+"\n  ["+R+"!"+W+"] Hash error"+W)
		ulang()
    #cek wordlist
	time.sleep(1)
	print (W+"  ["+G+"#"+W+"] Cek wordlist ..")
	try:
		w = open("wordlist.txt","r").readlines()
		x = len(w)
	except IOError:
		print (W+"  ["+R+"!"+W+"] Can't load "+W+"wordlist.txt, "+G+"file not exist\n"+W)
		sys.exit()		
	time.sleep(1)
	print (W+"  ["+G+"#"+W+"] Load "+G+"{}"+W+" words in "+G+"wordlist.txt").format(x)
	print (W+"\n  ["+G+"*"+W+"] Starting ..")	
	time.sleep(1)
	start = ("00:00:00")
	start1 = time.time()
	print (G+"  ["+W+"{}"+G+"] "+W+"Cracking..."+Y).format(start)
	pbar = progressbar.ProgressBar()   
    #mysql1323
	if hash == "mysql1323":
		hash_str = hash_str.lower()
		for line in pbar(w):
			line = line.strip()
			h = m20.encrypt(line)
			if h == hash_str:
				end = time.strftime("%H:%M:%S", time.gmtime(time.time() - start1))
				print (G+"  ["+W+"{}"+G+"] "+W+"Stopped...\n").format(end)
				time.sleep(0.3)
				print (W+"  ["+G+"+"+W+"] Password found ")
				print (W+"  ["+G+"+"+W+"] "+hash_str+" : "+G+line+"")
				ulang()
		end = time.strftime("%H:%M:%S", time.gmtime(time.time() - start1))
		print (G+"  ["+W+"{}"+G+"]"+W+" Password not found\n"+W).format(end)
		ulang()
    #lmhash
	elif hash == "lmhash":
		hasb_str = hash_str.upper()
		for line in pbar(w):
			line = line.strip()
			h = lmhash.encrypt(line)
			if h == hash_str:
			    end = time.strftime("%H:%M:%S", time.gmtime(time.time() - start1))
			    print (G+"  ["+W+"{}"+G+"] "+W+"Stopped...\n").format(end)
			    time.sleep(0.3)
			    print (W+"  ["+G+"+"+W+"] Password found ")
                print (W+"  ["+G+"+"+W+"] "+hash_str+" : "+G+line+"\n")
                sys.exit()
		end = time.strftime("%H:%M:%S", time.gmtime(time.time() - start1))
		print (G+"  ["+W+"{}"+G+"]"+W+" Password not found\n"+W).format(end)
		ulang()
    #nthash
	elif hash == "nthash":
		hasb_str = hash_str.upper()
		for line in pbar(w):
		    line = line.strip()
		    h = nthash.encrypt(line)
		    if h == hash_str:
		        end = time.strftime("%H:%M:%S", time.gmtime(time.time() - start1))
		        print (G+"  ["+W+"{}"+G+"] "+W+"Stopped...\n").format(end)
		        time.sleep(0.3)
		        print (W+"  ["+G+"+"+W+"] Password found ")
		        print (W+"  ["+G+"+"+W+"] "+hash_str+" : "+G+line+"\n")
		        sys.exit()
		end = time.strftime("%H:%M:%S", time.gmtime(time.time() - start1))
		print (G+"  ["+W+"{}"+G+"]"+W+" Password not found\n"+W).format(end)
		ulang()
    #mysql41
	elif hash == "mysql41":
		hash_str = hash_str.upper()
		for line in pbar(w):
			line = line.strip()
			h = m25.encrypt(line)
			if h == hash_str:
			    end = time.strftime("%H:%M:%S", time.gmtime(time.time() - start1))
		        print (G+"  ["+W+"{}"+G+"] "+W+"Stopped...\n").format(end)
		        time.sleep(0.3)
		        print (W+"  ["+G+"+"+W+"] Password found ")
		        print (W+"  ["+G+"+"+W+"] "+hash_str+" : "+G+line+"\n")
		        sys.exit()
		end = time.strftime("%H:%M:%S", time.gmtime(time.time() - start1))
		print (G+"  ["+W+"{}"+G+"]"+W+" Password not found\n"+W).format(end)
		ulang()
    #mssql2000
	elif hash == "mssql2000":
		hash_str = hash_str.upper()
		for line in pbar(w):
			line = line.strip()
			h = ms20.encrypt(line)
			if h == hash_str:
				end = time.strftime("%H:%M:%S", time.gmtime(time.time() - start1))
				print (G+"  ["+W+"{}"+G+"] "+W+"Stopped...\n").format(end)
				time.sleep(0.3)
				print (W+"  ["+G+"+"+W+"] Password found ")
				print (W+"  ["+G+"+"+W+"] "+hash_str+" : "+G+line+"\n")
				sys.exit()
		end = time.strftime("%H:%M:%S", time.gmtime(time.time() - start1))
		print (G+"  ["+W+"{}"+G+"]"+W+" Password not found\n"+W).format(end)
		ulang()
    #ntlm
	elif hash == "ntlm":
		hash_str = hash_str.lower()
		for line in pbar(w):
			line = line.strip()
			h = ntlm_hash = binascii.hexlify(hashlib.new('md4', line.encode('utf-16le')).digest())
			if h == hash_str:
			    end = time.strftime("%H:%M:%S", time.gmtime(time.time() - start1))
			    print (G+"  ["+W+"{}"+G+"] "+W+"Stopped...\n").format(end)
			    time.sleep(0.3)
			    print (W+"  ["+G+"+"+W+"] Password found ")
			    print (W+"  ["+G+"+"+W+"] "+hash_str+" : "+G+line+"\n")
			    sys.exit() 
		end = time.strftime("%H:%M:%S", time.gmtime(time.time() - start1))
		print (G+"  ["+W+"{}"+G+"]"+W+" Password not found\n"+W).format(end)
		ulang()
	#mssql2005
	elif hash == "mssql2005":
		hasb_str = hash_str.upper()
		for line in pbar(w):
		    line = line.strip()
		    h = ms25.encrypt(line)
		    if h == hash_str:
		        end = time.strftime("%H:%M:%S", time.gmtime(time.time() - start1))
		        print (G+"  ["+W+"{}"+G+"] "+W+"Stopped...\n").format(end)
		        time.sleep(0.3)
		        print (W+"  ["+G+"+"+W+"] Password found ")
		        print (W+"  ["+G+"+"+W+"] "+hash_str+Y+" : "+G+line+"\n")
		        sys.exit()
		end = time.strftime("%H:%M:%S", time.gmtime(time.time() - start1))
		print (G+"  ["+W+"{}"+G+"]"+W+" Password not found\n"+W).format(end)
		ulang()

	else:
		hash_str = hash_str.lower()
		for line in pbar(w):
			line = line.strip()
			h = hashlib.new(hash)
			h.update(line)
			if h.hexdigest() == hash_str:
				end = time.strftime("%H:%M:%S", time.gmtime(time.time() - start1))
				print (G+"  ["+W+"{}"+G+"] "+W+"Stopped...\n").format(end)
				time.sleep(0.3)
				print (W+"  ["+G+"+"+W+"] Password found ")
				print (W+"  ["+G+"+"+W+"] "+hash_str+" : "+G+line+"\n")
				sys.exit()
		end = time.strftime("%H:%M:%S", time.gmtime(time.time() - start1))
		print (G+"  ["+W+"{}"+G+"]"+W+" Password not found\n"+W).format(end)
		ulang() 

try:
    if sys.argv[1] == "-u" or sys.argv[1] == "--update" or sys.argv[1] == "-update":
        update()
    elif sys.argv[1] == "-e" or sys.argv[1] == "--enc" or sys.argv[1] == "-enc":
        os.system('clear') 
        enc()    
    elif sys.argv[1] == "-d" or sys.argv[1] == "--dnc" or sys.argv[1] == "-dnc":
        os.system('clear') 
        dnc()    
    elif sys.argv[1] == "-i" or sys.argv[1] == "--info" or sys.argv[1] == "-info":
        info()
    else:
        print (R+"  ["+W+"!"+R+"] "+G+"Command Error !!"+W)
        sys.exit()

except IndexError:
    hash()
