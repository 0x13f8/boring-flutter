import r2pipe
import time
import sys
import os
import shutil
import subprocess

search_scalar_verify_cert_chain = '0xb'
search_scalar_verify_peer_cert = '0x121'     # SSL_R_OCSP_CB_ERROR
search_string_ssl_client = 'ssl_client'


def argument_parsing():
    """
    Parse command-line arguments
    """
    if len(sys.argv) < 2:
        print('❌  Usage: python3 {} [libflutter.so | Flutter]'.format(sys.argv[0]))
        exit(-1)

    if not os.path.exists(sys.argv[1]):
        print('❌  File "{}" not found'.format(sys.argv[1]))
        exit(-1)

    if not os.path.isfile(sys.argv[1]):
        print('❌  "{}" is a directory, please provide a valid libflutter.so/Flutter file'.format(sys.argv[1]))
        exit(-1)
    return sys.argv[1]


def arch_parsing(r2):
    """
    Check the architecture of a binary
    """
    info = r2.cmdj('ij')
    info_bin = info.get('bin')
    if not info_bin:
        print('❌  File "{}" is not a binary'.format(sys.argv[1]))
        exit(0)

    if info_bin.get('arch') != 'arm':
        print('❌  Currently only supporting ARM')
        exit(0)

    if info_bin.get('class') == 'ELF32':
        return 32
    else:
        return info_bin.get('bits')


def platform_parsing(r2):
    """
    Check the OS supported by a binary
    """
    info = r2.cmdj('ij')
    platform = info.get('bin').get('os')

    if not (platform == 'android' or platform == 'ios'):
        print('❌  Currently only supporting Android and iOS')
        exit(0)

    return platform


def is_fat_binary(r2, file_path):
    """
    Check if a Mach-O binary is fat/universal (contains both 32-bit and 64-bit binaries in the same file)
    """
    info = r2.cmdj('ij')
    packet = info.get('core').get('packet')

    if packet == 'xtr.fatmach0':
        print('🔥 Found a fat binary')
        return True
    else:
        return False


def thin_binary(file_path):
    """
    Convert a universal Mach-O binary to a 64-bit binary
    """
    print('🔥 Thinning a fat binary to obtain a 64-bit version')
    newfile_path = os.path.join(os.getcwd(), 'Flutter64')

    try:
        subprocess.call(['lipo', '-thin', 'arm64', file_path, '-output', newfile_path])
    except:
        print('❌  Cannot thin a binary. Please check if the "lipo" command exists')
        exit(0)

    return newfile_path


def perform_64bits_analysis_verify_cert_chain(r2, platform):
    """
    Find an offset of the ssl_crypto_x509_session_verify_cert_chain() function in AArch64
    """
    print('🔥 Performing advanced analysis (64-bit)')
    if platform == 'android':
        r2.cmd('aaaa')
    elif platform == 'ios':
        r2.cmd('aa')

    print('🔥 Searching for the string "{}" (/ij {})'.format(search_string_ssl_client, search_string_ssl_client))
    search = r2.cmdj('/ij {}'.format(search_string_ssl_client))

    if len(search) == 0:
        print('❌  Could not find the string "{}" '.format(search_string_ssl_client))
        exit(0)       
    else:
        print('🔥 Found the string "{}" @ {}'.format(search_string_ssl_client, hex(search[0]['offset'])))
        print('🔥 Searching for a cross-reference of the string "{}" to find ssl_crypto_x509_session_verify_cert_chain()'.format(search_string_ssl_client))
        target = r2.cmdj('axtj {}'.format(search[0]['offset']))
        target = target[0]['fcn_addr']
        address = hex(target)
        print('🔥 Found ssl_crypto_x509_session_verify_cert_chain() @ {} '.format(address))
        return address


def perform_64bits_analysis_verify_peer_cert(r2, platform):
    """
    Find an offset of the ssl_verify_peer_cert() function in AArch64
    """
    print('🔥 Performing advanced analysis (64-bit)')
    if platform == 'android':
        r2.cmd('aaaa')
    elif platform == 'ios':
        r2.cmd('aa')

    print('🔥 Searching for instructions with scalar value (/aij {})'.format(search_scalar_verify_peer_cert))
    search = r2.cmdj('/aij {},'.format(search_scalar_verify_peer_cert))

    mov_instructions = []
    for hit in search:
        if hit['code'].startswith('mov'):
            print('\033[31m{} {}\033[0m'.format(hex(hit['offset']), hit['code']))
            mov_instructions.append(hit)
        else:
            print('{} {}'.format(hex(hit['offset']), hit['code']))

    if not mov_instructions:
        print('❌  Could not find an instruction with {} scalar value'.format(search_scalar_verify_peer_cert))
        exit(0)

    print('🔥 Performing simple instruction matching to find ssl_verify_peer_cert()')
    target = ''
    for mov_instruction in mov_instructions:
        instructions = r2.cmdj('pdj 3 @{}'.format(mov_instruction['offset']))
        if len(instructions) == 3 and instructions[1]['disasm'].startswith('mov') and instructions[2]['disasm'].startswith('bl'):
            print('✅  {} {} (match)'.format(hex(mov_instruction['offset']), mov_instruction['code']))
            target = hex(mov_instruction['offset'])
            break
        else:
            print('❌  {} {} (no match)'.format(hex(mov_instruction['offset']), mov_instruction['code']))

    if not target:
        print('❌  Could not find a matching function ')
        exit(0)

    print('🔥 Seeking to target (s {})'.format(target))
    r2.cmd('s {}'.format(target))

    fcn_addr = r2.cmd('afi.')
    address = '0x' + fcn_addr.split('.')[-1].strip()

    print('🔥 Found ssl_verify_peer_cert() @ {} (afi.)'.format(address))
    return address


def perform_32bits_analysis_verify_cert_chain(r2, platform):
    """
    Find an offset of the ssl_crypto_x509_session_verify_cert_chain() function in 32-bit ARM
    """
    print('🔥 Performing advanced analysis (32-bit)')
    if platform == 'android':
        r2.cmd('aaaa')
    elif platform == 'ios':
        r2.cmd('aa')

    print('🔥 Searching for instructions with scalar value (/aij {})'.format(search_scalar_verify_cert_chain))
    search = r2.cmdj('/aij {},'.format(search_scalar_verify_cert_chain))

    mov_instructions = []
    for hit in search:
        if hit['code'].startswith('mov'):
            # print('\033[31m{} {}\033[0m'.format(hex(hit['offset']), hit['code']))
            mov_instructions.append(hit)

    if not mov_instructions:
        print('❌  Could not find an instruction with {} scalar value'.format(search_scalar_verify_cert_chain))
        exit(0)

    print('🔥 Performing simple instruction matching to find ssl_crypto_x509_session_verify_cert_chain()')
    target = ''
    for mov_instruction in mov_instructions:
        # print('🔥 Find prelude for current offset @ {}'.format(hex(mov_instruction['offset'])))
        try:
            r2.cmd('s {}'.format(mov_instruction['offset']))
            prelude = r2.cmd('ap').splitlines()[-1]

            # print('🔥 Pattern matching on prelude @ {}'.format(prelude))
            instructions = r2.cmdj('pdj 5 @{}'.format(prelude))
            if len(instructions) == 5 and instructions[0]['type'] == 'push' and instructions[1]['type'] == 'sub'\
                    and instructions[2]['type'] == 'mov' and instructions[3]['type'] == 'mov'\
                    and instructions[3]['val'] == 0x50 and instructions[4]['type'] == 'store':
                print('✅  scalar offset @ {} -> prelude offset @ {} (match)'.format(mov_instruction['offset'], prelude))
                target = prelude
                break
        except:
            continue

    if not target:
        print('❌  Could not find a matching function')
        exit(0)

    print('🔥 Found ssl_crypto_x509_session_verify_cert_chain() @ {} '.format(target))
    return hex(int(target, 16))


def save_to_frida_script(address, platform):
    """
    Write an address offset of the target function to a new Frida script
    """
    if platform == 'android':
        with open('template_frida_hook_android.js') as f:
            template = f.read()
    elif platform == 'ios':
        with open('template_frida_hook_ios.js') as f:
            template = f.read()

    output_script = 'frida_flutter_{}_{}.js'.format(platform, time.strftime("%Y%m%d"))
    with open(output_script, 'w') as f:
        f.write(template.replace('0x00000000', address))
    print('🔥 Wrote a script to: {}'.format(output_script))


def save_to_patched_binary(address, platform, bits, file):
    """
    Patch libflutter.so/Flutter and write to a new binary file as follows:
    - [Android] ssl_crypto_x509_session_verify_cert_chain(): returns 1
    - [iOS] ssl_verify_peer_cert(): returns 0
    """
    output_binary = '{}_{}'.format(file, time.strftime("%Y%m%d"))
    shutil.copy(file, output_binary)
    r2 = r2pipe.open(output_binary, flags=['-w', '-2'])     # writable mode, disable stderr
    r2.cmd('s {}'.format(address))

    if platform == 'android':
        if bits == 64:
            r2.cmd('wa mov x0, 1')
            r2.cmd('s+4')
            r2.cmd('wa ret')
        elif bits == 32:
            r2.cmd('wa mov.w r0, 1')
            r2.cmd('s+4')
            r2.cmd('wa bx lr')
    elif platform == 'ios':
            r2.cmd('wa mov x0, 0')
            r2.cmd('s+4')
            r2.cmd('wa ret')

    print('🔥 Wrote a binary to: {}'.format(output_binary))


if __name__ == "__main__":
    start_time = time.time()
    file = argument_parsing()
    r2 = r2pipe.open(file, flags=['-2'])                    # disable stderr
    bits = arch_parsing(r2)
    platform = platform_parsing(r2)
    print('🔥 Detected {} ARM'.format(platform))

    if platform == 'ios':
        if is_fat_binary(r2, file):
            newfile = thin_binary(file)
            r2 = r2pipe.open(newfile, flags=['-2'])         # disable stderr
        address = perform_64bits_analysis_verify_peer_cert(r2, platform)
    elif platform == 'android':
        if bits == 32:
            address = perform_32bits_analysis_verify_cert_chain(r2, platform)
        elif bits == 64:
            address = perform_64bits_analysis_verify_cert_chain(r2, platform)
    else:
        print('❌  Quantum???')
        exit(-1)

    save_to_frida_script(address, platform)
    save_to_patched_binary(address, platform, bits, file)

    print('🚀 exec time: {}s'.format(time.time() - start_time))
