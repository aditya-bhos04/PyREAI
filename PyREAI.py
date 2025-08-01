from pwn import *
from elftools.common.exceptions import ELFError
from termcolor import colored
from openai import OpenAI
import re
import sys

def print_protections(elf):
    print("\n\033[1;36mProtections:\033[0m")
    print(f"\033[1;33mRELRO:\033[0m    \033[1;35m{'Full' if elf.relro else 'Partial' if elf.relro == 1 else 'No'}\033[0m")
    print(f"\033[1;33mStack:\033[0m    \033[1;35m{'Canary found' if elf.canary else 'No canary'}\033[0m")
    print(f"\033[1;33mNX:\033[0m       \033[1;35m{'Enabled' if elf.nx else 'Disabled'}\033[0m")
    print(f"\033[1;33mPIE:\033[0m      \033[1;35m{'Enabled' if elf.pie else 'Disabled'}\033[0m")
    print(f"\033[1;33mRPATH:\033[0m    \033[1;35m{'Present' if elf.rpath else 'Not present'}\033[0m")
    print(f"\033[1;33mRUNPATH:\033[0m  \033[1;35m{'Present' if elf.runpath else 'Not present'}\033[0m")

def print_info(elf):
    print("\n\033[1;36mBinary Info:\033[0m")
    print(f"\033[1;33mArch:\033[0m \033[1;35m{elf.arch}\033[0m")
    print(f"\033[1;33mBits:\033[0m \033[1;35m{elf.bits}\033[0m")
    print(f"\033[1;33mOS:\033[0m \033[1;35m{elf.os}\033[0m")
    print(f"\033[1;33mType:\033[0m \033[1;35m{elf.elftype}\033[0m")
    print(f"\033[1;33mEntry:\033[0m \033[1;35m{hex(elf.entry)}\033[0m")
    print(f"\033[1;33mStripped:\033[0m \033[1;35m{elf.stripped}\033[0m")

def extract_strings_with_offsets(filename, min_length=4):
    try:
        with open(filename, "rb") as f:
            data = f.read()

        # Regex to match printable ASCII sequences of min_length+
        pattern = rb"([ -~]{%d,})" % min_length
        print(colored("\n[+] Extracting Printable Strings from Binary (with offsets):", "cyan", attrs=["bold"]))

        for match in re.finditer(pattern, data):
            offset = match.start()
            string = match.group().decode('ascii', errors='ignore')
            print(
                colored(f"0x{offset:08x}", "green") + " : " + colored(string, "yellow")
            )

    except FileNotFoundError:
        print(colored("[-] File not found", "red"))
    except Exception as e:
        print(colored(f"[-] Error: {e}", "red"))


def ask_ai(function_code):
    try:
        client = OpenAI(api_key="OPENAI-API-KEY")  # Replace with your real key
        print(colored("\n[+] Analyzing your code through AI", "green", attrs=["bold"]))
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "user", "content": function_code}
            ]
        )
        raw_output = response.choices[0].message.content.strip()

        # Remove Markdown syntax
        cleaned = raw_output
        cleaned = re.sub(r"`+", "", cleaned)                       # Remove code ticks
        cleaned = re.sub(r"\*\*(.*?)\*\*", r"\1", cleaned)         # Remove bold
        cleaned = re.sub(r"#+ ", "", cleaned)                      # Remove headers like ###, ##
        cleaned = re.sub(r"^- ", "* ", cleaned, flags=re.MULTILINE)  # Normalize bullets
        lines = cleaned.splitlines()

        print(colored("\n[AI Output]:", "magenta", attrs=["bold"]))
        for line in lines:
            if line.strip().startswith("*"):
                print(colored(line, "yellow"))
            elif ":" in line and not line.strip().startswith("0x"):
                key, val = line.split(":", 1)
                print(colored(key + ":", "blue", attrs=["bold"]), colored(val.strip(), "white"))
            elif line.strip():
                print(colored(line, "white"))
            else:
                print("")

    except Exception as e:
        err_msg = str(e).lower()

        if "no api key" in err_msg or "unauthorized" in err_msg or "401" in err_msg:
            print(colored("[!] OpenAI API Error: Missing or invalid API key.", "red", attrs=["bold"]))
            print(colored("    ➜ Set your API key using `OpenAI(api_key=\"your-key\")`", "yellow"))
        
        elif "rate limit" in err_msg or "429" in err_msg:
            print(colored("[!] Rate limit exceeded. Please wait a few seconds and try again.", "red", attrs=["bold"]))
            print(colored("    ➜ You can upgrade or check usage at: https://platform.openai.com/account/usage", "yellow"))

        else:
            print(colored(f"[!] OpenAI API Error: {e}", "red"))

        return False
def binary_functions(elf):
    print("\n" + colored("Functions of the Binary:", "blue", attrs=["bold"]))

    try:
        for function in elf.functions.values():
            try:
                function_name = function.name
                function_addr = function.address
                function_size = function.size

                # Print function header
                print("\n" + colored(
                    f"Assembly for function '{function_name}' (0x{function_addr:x}, size: {function_size} bytes):",
                    "green", attrs=["bold"]
                ))

                # Get disassembly
                disassembly = disasm(elf.read(function_addr, function_size), vma=function_addr)

                # Print disassembly first
                for line in disassembly.split('\n'):
                    if ':' in line:
                        addr, rest = line.split(':', 1)
                        print(colored(addr + ':', 'cyan'), end='')
                        if '#' in rest:
                            instr, comment = rest.split('#', 1)
                            print(colored(instr, 'yellow') + colored('#' + comment, 'green'))
                        else:
                            print(colored(rest, 'yellow'))
                    else:
                        print(line)

                # Then call the AI after printing
                ask_ai(disassembly)


            except Exception as e:
                print(colored(f"[-] Failed to disassemble function {function_name}: {str(e)}", "red"))
    except AttributeError:
        print(colored("[-] No functions found in binary", "red"))
    except Exception as e:
        print(colored(f"[-] Error processing functions: {str(e)}", "red"))

def main():
    program = input("Enter the Program Name (Case Sensitive) :- ")

    try:
        elf = context.binary = ELF(program, checksec=False)
        print_protections(elf)
        print_info(elf)
        binary_functions(elf)
        extract_strings_with_offsets(program)
    except FileNotFoundError:
        print("\n\033[31m[-] File Does not exist\033[0m")
    except ELFError:
        print("\n\033[31m[-] Not a Valid ELF Binary\033[0m")
    except Exception as e:
        print(f"\n\033[31m[-] Something went Wrong: {e}\033[0m")

if __name__ == "__main__":
    main()
