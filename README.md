1.a Write a program in java to implement Caesar Cipher Technique

import java.io.*;
class CaesarCipher
{
	public static void main(String []args)throws Exception
	{
		String plaintxt,ciphertxt="";
		BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
		System.out.print("Enter plain text : ");
		plaintxt = br.readLine();
		plaintxt = plaintxt.toLowerCase();
		for(int i=0;i<plaintxt.length();i++)
		{
			char c = plaintxt.charAt(i);
			int x = c;
			if(x>=97 && x<=122)
			{
				x += 3;
				if(x > 122)
				{
					x -= 26;
				}
			}
			c = (char)x;
			ciphertxt += c;
		}
		System.out.println("Encrypted Text : "+ciphertxt);	
		plaintxt="";
		for(int i=0;i<ciphertxt.length();i++)
		{
			char c = ciphertxt.charAt(i);
			int x = c;
			if(x>=97 && x<=122)
			{
				x = x-3;
				if(x<97)
				{
					x+=26;
				}	
			}
			c = (char)x;
			plaintxt += c;
		}
		System.out.println("Decrypted Text : "+plaintxt);	
	}
}

Output:

 

1.b Write a program in java to implement Modified Caesar Cipher Technique.

import java.io.*;
class ModCaesarCipher
{
	public static void main(String [] args)throws Exception
	{
		String plaintxt,ciphertxt="";
		BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
		System.out.print("Enter plain text : ");
		plaintxt = br.readLine();
		plaintxt = plaintxt.toLowerCase();
		System.out.print("Enter key value : ");
		int key = Integer.parseInt(br .readLine());
		key=key%26;
		for(int i=0;i<plaintxt.length();i++)
		{
			char c = plaintxt.charAt(i);
			int x = c;

			if(x>=97 && x<=122)
			{
				x += key;
				if(x > 122)
				{
				    x -= 26;
				}	
			}
			c = (char)x;
			ciphertxt += c;
		
		}
		System.out.println("Encrypted Text : "+ciphertxt);	
		plaintxt="";	
		for(int i=0;i<ciphertxt.length();i++)
		{
			char c = ciphertxt.charAt(i);
			int x = c;
			if(x>=97 && x<=122)
			{
				x = x-key;
				if(x<97)
				{
				     x+=26;
				}	
			}
			c = (char)x;
			plaintxt += c;
		}
		System.out.println("Decrypted Text : "+plaintxt);	
	}
}

Output:

 


1.c Write a program in java to implement Mono alphabetic Cipher.
import java.io.*;
class Mono_alpha
{
    	public static void main(String args[]) throws IOException
    	{
  	BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
  	//For Encryption
 char[]  key1= {'b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','a'};
		String ciphertext="";
System.out.print("Enter plaintext : ");
		String plaintext=br.readLine();
		plaintext=plaintext.toLowerCase();
   		for(int i=0; i<plaintext.length(); i++)
  		{
     			int asci_plaintext=plaintext.charAt(i);
     			asci_plaintext=asci_plaintext-97;
     			char c=key1[asci_plaintext];
     			ciphertext+=c;         
  		}
  		System.out.println("Ciphertext is = "+ciphertext);

		//For Decryption
char[]  key2= {'z','a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y'};
		plaintext="";
for(int i=0; i<ciphertext.length(); i++)
  		{
     			int ascii_ciphertext=ciphertext.charAt(i);
     			ascii_ciphertext=ascii_ciphertext-97;
     			char c=key2[ascii_ciphertext];
     			plaintext+=c;    
  		}
  		System.out.println("Plaintext is = "+plaintext);  
  	  } 
 }


Output:

 


1.d  Write a program in java to implement Polyalphabetic -Vigenere Cipher.

import java.io.*;
class vigener_new{	
public static String makekey(String plaintext, String key)
	{
		while(key.length()<=plaintext.length())
			{
    			key += key;
			}
   		key = key.substring(0,plaintext.length());
		return key;		
	}
public static String encrypt(String plaintext,String key)
	{
		String alphabet ="abcdefghijklmnopqrstuvwxyz";		
		plaintext=plaintext.toLowerCase();
		key=key.toLowerCase();
     	          String ciphertext="";
	   	char replaceval;
  for(int i=0;i<plaintext.length();i++)
		{
			if(plaintext.charAt(i)==' ')
				replaceval=' ';
			else
			{ 
		           int charposition = alphabet.indexOf(plaintext.charAt(i));
                		int keyval = alphabet.indexOf(key.charAt(i));
		         replaceval = alphabet.charAt((keyval+charposition)%26);
			}
	                ciphertext += replaceval;		
           	}
		ciphertext = ciphertext.toUpperCase();
           	return ciphertext;
     }
public static String decrypt(String ciphertext, String key)
     	{
		String alphabet ="abcdefghijklmnopqrstuvwxyz";
        	          ciphertext = ciphertext.toLowerCase();
		key=key.toLowerCase();
           	String plaintext="";
	   	char replaceval;
           	for(int i=0;i<ciphertext.length();i++)
           	{
			if(ciphertext.charAt(i)==' ')
				replaceval=' ';
			else
			{
                		int charposition = alphabet.indexOf(ciphertext.charAt(i));
                		int keyval = alphabet.indexOf(key.charAt(i));

if((charposition-keyval)<0)
		   replaceval = alphabet.charAt((charposition-keyval)+26);
else
		        replaceval = alphabet.charAt((charposition-keyval)%26);
                	}
                	plaintext += replaceval;
           	}
           	return plaintext;
     }
	public static void main(String args[]) throws IOException
	{
		String plaintext,ciphertext,key;
	BufferedReader br=new BufferedReader(new InputStreamReader(System.in));
		System.out.println("Enter the plain text");
		plaintext = br.readLine();
		System.out.println("Enter a text key : ");
		key = br.readLine();
		key = makekey(plaintext, key);
		System.out.println("Key : "+key);
		ciphertext = encrypt(plaintext,key);
		System.out.println("cipher text : "+ciphertext);
		plaintext = decrypt(ciphertext,key);
		System.out.println("plain text : " +plaintext);
	}
}


Output:


2.a  Write a program in java to implement Railfence Technique.

import java.io.*;
class RailFence
{
	public static void main(String[] args) throws Exception
	{
		String plaintxt,ciphertxt;
	BufferedReader br =new BufferedReader(new InputStreamReader(System.in));

		System.out.println("RAIL FENCE TECHNIQUE FOR ENCRYPTION");
		System.out.println("Enter the message to be encrypted\n");

		plaintxt=br.readLine();
		int len=plaintxt.length();
		String s1="",s2="";

		for(int i=0;i<len;i++)
		{
			if(i%2==0)
				s1=s1+plaintxt.charAt(i);
			else
				s2=s2+plaintxt.charAt(i);			
		}
		ciphertxt=s1.concat(s2);
		System.out.println("The Cipher text is "+ciphertxt);

		System.out.println("\nDo you want to Decrypt the cipher text : ");
		String choice=br.readLine();

		plaintxt="";
		if(choice.equalsIgnoreCase("yes")==true)
		{
			for(int i=0;i<(len/2);i++)
			{
				plaintxt=plaintxt+s1.charAt(i)+s2.charAt(i);
			}
			if(len%2!=0)
				plaintxt=plaintxt+s1.charAt(len/2);
			System.out.println("The Decrypted message is "+plaintxt);
		}
		else
			System.exit(0);
	}
}

Output:


 

2.b  Write a program in java to implement Vernam Cipher.

import java.io.*;
import java.util.*;
class Vernam
{
	static String charset="abcdefghijklmnopqrstuvwxyz ";
	public static int getIndex(char s)
	{	
		int indx=0;
		for(int i=0;i<27;i++)
			if(charset.charAt(i)==s)	
				indx=i;
		return indx;
	}
	public static void main(String[] args) throws Exception
	{
		String plaintxt,key,ciphertxt="";
	BufferedReader br=new BufferedReader(new InputStreamReader(System.in));

	System.out.println("VERNAM  TECHNIQUE FOR ENCRYPTION");
          System.out.println("Enter the message to be encrypted\n");
		
          plaintxt=br.readLine();
		int len=plaintxt.length();
		int indx1,indx2,indx;
	System.out.println("Enter the key to be used for the encryption: ");	
	key=br.readLine();
	   if (key.length()<len)
              {
                System.out.println("Encryption not possible");
              }
           else
              {
		for(int i=0;i<len;i++)
		{
			indx1=getIndex(plaintxt.charAt(i));
			indx2=getIndex(key.charAt(i));

			indx=(indx1+indx2)%27;
			ciphertxt=ciphertxt+charset.charAt(indx);		
		}
		System.out.println("The Cipher text is "+ciphertxt);

		System.out.println("\nDo you want to Decrypt the cipher text : ");
		String choice=br.readLine();
		plaintxt="";
		if(choice.equalsIgnoreCase("yes")==true)
		{
			for(int i=0;i<len;i++)
			{
				indx1=getIndex(ciphertxt.charAt(i));
				indx2=getIndex(key.charAt(i));
				indx=indx1-indx2;
				if(indx<0)
					indx=27+indx;
				else
					indx=indx%27;
				plaintxt=plaintxt+charset.charAt(indx);
			}
			System.out.println("The Decrypted message is "+plaintxt);
		}
		else
			System.exit(0);
              }
	}
}

Output:


 
Q.2(c).AIM:-Write a program to implement Simple Column Cipher to convert plain text  to cipher text and decrypt it back to plain text.

PROGRAM:-
package simplecol;
import java.io.IOException;
import java.util.Scanner;
public class Simplecol
{
    String str,total="";
    int x,y,z=0,a,b,m,i,j;
    char twoD[][];
    Scanner sc;
    Simplecol()
    {
    sc=new Scanner(System.in);
    System.out.print("Enter X row=");
    x=sc.nextInt();
    System.out.print("Enter y col=");
    y=sc.nextInt();
    a=x*y;
    System.out.print("Enter the text=");
    str=sc.next();
    b=str.length();
    System.out.println();
    if(b<a)
    {
        System.out.print("ERROR=More Characters:");
                }
    else
    {
        char twoD[][]=new char[x][y];
        int i,j,k=0,z=0;
        for(i=0;i<x;i++)
        {
            for(j=0;j<y;j++)
            {
                twoD[i][j]=str.charAt(z);
                System.out.print(twoD[i][j]+"");
                z++;
            }
            System.out.println();
        }
        while(i>0)
        {
            System.out.print("Enter the column number(0 to n)=");
            m=sc.nextInt();
            i--;
            i=y;
            if(m<i)
            {}
            else
            {
                System.out.println("BREAKING....");
                break;
            }
            for(i=0;i<x;i++)
            {
                for(j=m;j<=m;j++)
                {
                total=total+twoD[i][j];
            }
        }
    }
    System.out.println("CIPHER TEXT="+total);
    }
}
public static void main(String[]
args)
{
Simplecol ob=new Simplecol();
    }
  }

Output:

 



Q.2(c) .AIM:- Write a program to implement Multi Column Cipher to convert plain text  to cipher text and decrypt it back to plain text.

PROGRAM:-

package multiple;

import java.util.Scanner;
public class multiple{

    
    String str,total="";
    String str1;
    int x,y,z=0,a,b,m,i,j;
    char twoD[][];
    Scanner sc;
    multiple()
            {
                sc=new Scanner(System.in);
                System.out.print("\n enter the text :");
                str=sc.next();
                
                do
                { 
                System.out.print("\n enter x row: ");
                x=sc.nextInt();
                System.out.print("\n enter y col: ");
                y=sc.nextInt();
                a=x*y;
                
                
                b=str.length();
                System.out.println();
                if(b<a)
                {
                    System.out.println("ERROR:=MORE CHARACTERS");
                    
                }
                else
                {
                    char twoD[][]=new char[x][y];
                int i,j,k=0,z=0;
                for(i=0;i<x;i++)
                {
                    for(j=0;j<y;j++)
                    {
                        twoD [i][j]=str.charAt(z);
                        System.out.print(twoD[i][j]+" ");
                        z++;
                    }
                    System.out.println();
                }
                total="";
                while(i>=0)
                {
                    System.out.print("\n enter the column number (0 to n):");
                    m=sc.nextInt();
                    i--;
                    i=y;
                    if(m<i)
                    {}
                    else
                    {
                        System.out.println("breaking........");
                        break;
                        
                    } 
                    for(i=0;i<x;i++)
                    {
                    for(j=m;j<=m;j++)
                    {
                        total=total+twoD[i][j]; 
                    }
                    }
                }
                System.out.println("\n cipher text: "+total);
                }
                System.out.println("do you want to do next round then press Y/N :");
                str1=sc.next();
               str=total;
            }while(str1.equals("Y")==true);
                }
     public static void main(String args[] )
    {
       multiple ob=new  multiple ();
    }
}
   OUTPUT:




 
Q1) Write a program to generate symmetric keys for Diffie Hellman algorithm.

import java.io.*;
import java.math.*;
import java.security.*;

public class Diffie_hellman 
{
    BigInteger n,g,x,y,a,b;
    SecureRandom r;
    public Diffie_hellman()throws IOException
    {
        r=new SecureRandom();
        n=new BigInteger(512,100,r);
        g=new BigInteger(512,100,r);
        
        System.out.println("Prime no n is "+n.intValue());
        System.out.println("Prime no g is "+g.intValue());
        BufferedReader br=new BufferedReader(new InputStreamReader(System.in));
        
        System.out.print("Enter x=");
        BigInteger x=new BigInteger(br.readLine());
        System.out.print("Enter y=");
        BigInteger y=new BigInteger(br.readLine());
        
        BigInteger cal_a=calculate(g,x,n);
        System.out.println("A="+cal_a.intValue());
        BigInteger cal_b=calculate(g,y,n);
        System.out.println("B="+cal_b.intValue());
        
        BigInteger cal_k1=calculate(cal_b,x,n);
        System.out.println("K1="+cal_k1.intValue());
        BigInteger cal_k2=calculate(cal_a,y,n);
        System.out.println("K2="+cal_k2.intValue());
      }
    BigInteger calculate(BigInteger l,BigInteger m,BigInteger n)
    {
        return l.modPow(m, n);
    }
    
    public static void main(String[] args) throws IOException
    {
    new Diffie_hellman();
    }
}




Output:


Q.1) Write a program to implement DES to convert plain text into cipher text and decrypt it                   back to the plain text.

Program:


package desc;

import javax.crypto.*;
import java.io.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.spec.*;
import javax.crypto.spec.IvParameterSpec;
import java.lang.*;

public class Desc{
       Cipher ecipher;
       Cipher dcipher;
       Desc(SecretKey Key){
        try{
            ecipher=Cipher.getInstance("DES");
            dcipher=Cipher.getInstance("DES");
            ecipher.init(Cipher.ENCRYPT_MODE,Key);
            dcipher.init(Cipher.DECRYPT_MODE,Key);
        }
        catch(javax.crypto.NoSuchPaddingException e){}
        catch(java.security.NoSuchAlgorithmException e){}
        catch(java.security.InvalidKeyException e){}
        }
        public String encrypt(String str)
        {
            try
            {
                byte[] utf8=str.getBytes("UTF8");
                byte[] enc=ecipher.doFinal(utf8);
                return new sun.misc.BASE64Encoder().encode(enc);
            }
            catch(javax.crypto.BadPaddingException e){}
            catch(IllegalBlockSizeException e){}
            catch(UnsupportedEncodingException e){}
            catch(java.io.IOException e){}
            return null;
        }

        public String decrypt(String str)
        {
            try
            {
                byte[] dec= new sun.misc.BASE64Decoder().decodeBuffer(str);
                byte[] utf8=dcipher.doFinal(dec);
                return new String(utf8,"UTF8");
            }
            catch(javax.crypto.BadPaddingException e){}
            catch(IllegalBlockSizeException e){}
            catch(UnsupportedEncodingException e){}
            catch(java.io.IOException e){}
            return null;
        }

    public static void main(String[] args)
    {
          System.out.println();
          try{
              SecretKey Key=KeyGenerator.getInstance("DES").generateKey();
               Desc encrypter=new Desc(Key);
              String s="shraddha";
              String encrypted=encrypter.encrypt(s);
             String decrypted=encrypter.decrypt(encrypted);
               System.out.println("original string is :"+s);
              System.out.println("encrypted string is :"+encrypted);
              System.out.println("decrypted string is :"+decrypted);
          }
          catch(Exception e)
          {}
    }
}

Q.)Aim:-Write a program to implement AES to convert plain text to cipher text and to decrypt it back to plain text.

Program:

package AES;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class AES{
    public static void main(String [] args) throws Exception
    {
         BufferedReader br=new BufferedReader(new InputStreamReader(System.in));
         KeyGenerator kg=KeyGenerator.getInstance("AES");
         SecretKey sk= kg.generateKey();
         Cipher cp=Cipher.getInstance("AES");
         cp.init(Cipher.ENCRYPT_MODE,sk);
         System.out.println("Enter plain text");
         String str=br.readLine();
         byte[] enc=cp.doFinal(str.getBytes());
         String encryp=new sun.misc.BASE64Encoder().encode(enc);
         System.out.println("encrypted msg:"+new String(encryp));
         cp.init(Cipher.DECRYPT_MODE,sk);
         byte[] dec=new sun.misc.BASE64Decoder().decodeBuffer(encryp);
         byte[] decryp=cp.doFinal(dec);
         System.out.println("decrypted msg:"+new String(decryp));
         System.exit(0);
    }
}

Output:


Q)Write a program to implement RC4 for converting plaintext into cipher text

import java.io.IOException;
import java.io.BufferedReader;
import java.io.InputStreamReader;
public class RC4
{
    String strplaintext;
    static char Cipher[];
  public RC4(String strplaintext,int []key)
    {
        this.strplaintext=strplaintext;
        int s[]=new int[255];
        Cipher=new char[strplaintext.length()];
        for(int i=0;i<s.length;i++)
        {
            s[i]=i;
        }
        int i=0;
        int j=0;
        for(int k=0;k<strplaintext.length();k++)
        {
            int modk=(k%key.length);
            int kc=key[modk];
            j=(s[i]+j+kc)%256+1;
            int temp=s[i];
            s[i]=s[j];
            s[j]=temp;
            int sc=(s[i]+s[j])%256;
            int ck=s[sc];
            Cipher[k]=(char)(ck^(int)strplaintext.charAt(k));
            i=i+1;
        }
    }

    
    public static void main(String[] args)throws IOException
    {
        int k[]={1,2,3,4,5};
        String stroriginal;
        BufferedReader br=new BufferedReader(new InputStreamReader(System.in));
        System.out.println("Enater plaintext:");
        stroriginal=br.readLine();
        System.out.println("Ciphertext:");
        new RC4(stroriginal,k);
        for(int i=0;i<Cipher.length;i++)
        {
            System.out.print(""+Cipher[i]+"");
        }
        
    }
}

Output:


Q.)Aim:-Write a program to implement BLOWFISH to convert plain text to cipher text and to decrypt it back toplain text.

Program:

package blowfish;



importjava.io.BufferedReader;
importjava.io.InputStreamReader;
importjavax.crypto.Cipher;
importjavax.crypto.KeyGenerator;
importjavax.crypto.SecretKey;

public class BLOWFISH{
public static void main(String [] args) throws Exception
    {
BufferedReaderbr=new BufferedReader(new InputStreamReader(System.in));
KeyGenerator kg=KeyGenerator.getInstance("BLOWFISH");
SecretKeysk= kg.generateKey();
         Cipher cp=Cipher.getInstance("BLOWFISH");
cp.init(Cipher.ENCRYPT_MODE,sk);
System.out.println("Enter plain text");
         String str=br.readLine();
byte[] enc=cp.doFinal(str.getBytes());
         String encryp=new sun.misc.BASE64Encoder().encode(enc);
System.out.println("encrypted msg:"+new String(encryp));
cp.init(Cipher.DECRYPT_MODE,sk);
byte[] dec=new sun.misc.BASE64Decoder().decodeBuffer(encryp);
byte[] decryp=cp.doFinal(dec);
System.out.println("decrypted msg:"+new String(decryp));
System.exit(0);
    }
}
Output:



Q1)Write a program to implement RSA algorithm to convert plain text to cipher text and to decrypt                                           it back to plain text

import java.io.*;
import java.util.*;
import java.math.*;
public class Rsa1 
{
    public static void main(String[] args)throws IOException {
        BigInteger p=new BigInteger("7");
        BigInteger q=new BigInteger("17");
        
        BigInteger n=p.multiply(q);
         System.out.println("The value of p and q is:" +p+" "+q);
         BigInteger p1=p.subtract(new BigInteger("1"));
         BigInteger q1=q.subtract(new BigInteger("1"));
         BigInteger ph=p1.multiply(q1);
         BigInteger e=new BigInteger("5");

         while(ph.gcd(e).intValue()>1||e.compareTo(ph)!=-1)
             e=e.add(new BigInteger("1"));
         BigInteger d=e.mod(ph);

          System.out.println("public key is("+n.intValue()+"."+e.intValue()+")");
          System.out.println("pvt key is("+n.intValue()+"."+d.intValue()+")");
         
          Scanner input=new Scanner(System.in);
          System.out.print("enter the no to be encrypted");
          BigInteger x=input.nextBigInteger();
          BigInteger ek=x.pow(e.intValue());
          ek=ek.mod(n);
          System.out.println("Encryption :" +ek);
          
          BigInteger dk=ek.pow(e.intValue());
          dk=dk.mod(n);
          System.out.println("Decryption :" +dk);
        
    }
}


OUTPUT:
