import r2pipe
import time
import sys
import os
import subprocess

search_scalar_verify_cert_chain = '0x186'
search_scalar_verify_peer_cert = '0x121'     # SSL_R_OCSP_CB_ERROR


def argument_parsing():
    if len(sys.argv) < 2:
        print('❌  Usage: python3 {} [libflutter.so | Flutter]'.format(sys.argv[0]))
        exit(-1)

    if not os.path.exists(sys.argv[1]):
        print('❌  File "{}" not found...'.format(sys.argv[1]))
        exit(-1)

    if not os.path.isfile(sys.argv[1]):
        print('❌  "{}" is a directory, please provide a valid libflutter.so/Flutter file...'.format(sys.argv[1]))
        exit(-1)
    return sys.argv[1]


def arch_parsing(r2):
    info = r2.cmdj('ij')
    info_bin = info.get('bin')
    if not info_bin:
        print('❌  File "{}" is not a binary...'.format(sys.argv[1]))
        exit(0)

    if info_bin.get('arch') != 'arm':
        print('❌  Currently only supporting ARM...')
        exit(0)

    if info_bin.get('class') == 'ELF32':
        return 32
    else:
        return info_bin.get('bits')

def platform_parsing(r2):
    info = r2.cmdj('ij')
    platform = info.get('bin').get('os')

    if not (platform == 'android' or platform == 'ios'):
        print('❌  Currently only supporting Android and iOS...')
        exit(0)

    return platform

def is_fat_binary(r2, file_path):
    info = r2.cmdj('ij')
    packet = info.get('core').get('packet')

    if packet == 'xtr.fatmach0':
        print('🔥 Found a fat binary...')
        return True
    else:
        return False

def thin_binary(file_path):
    print('🔥 Thinning a fat binary to obtain a 64-bit version...')
    newfile_path = os.path.join(os.getcwd(), 'Flutter64')

    try:
        subprocess.call(['lipo', '-thin', 'arm64', file_path, '-output', newfile_path])
    except:
        print('❌  Cannot thin a binary. Please check if the "lipo" command exists...')
        exit(0)

    return newfile_path

def perform_64bits_analysis_verify_cert_chain(r2, platform):
    print('🔥 Performing Advanced analysis...')
    if platform == 'android':
        r2.cmd('aaaa')
    elif platform == 'ios':
        r2.cmd('aa')

    print('🔥 Searching for instructions with scalar value (/aij {})...'.format(search_scalar_verify_cert_chain))
    search = r2.cmdj('/aij {},'.format(search_scalar_verify_cert_chain))

    mov_instructions = []
    for hit in search:
        if hit['code'].startswith('mov'):
            print('\033[31m{} {}\033[0m'.format(hex(hit['offset']), hit['code']))
            mov_instructions.append(hit)
        else:
            print('{} {}'.format(hex(hit['offset']), hit['code']))

    if not mov_instructions:
        print('❌  Could not find an instruction with {} scalar value...'.format(search_scalar_verify_cert_chain))
        exit(0)

    print('🔥 Performing simple instruction matching to find ssl_crypto_x509_session_verify_cert_chain()...')
    target = ''
    for mov_instruction in mov_instructions:
        instructions = r2.cmdj('pdj 3 @{}'.format(mov_instruction['offset']))
        if len(instructions) == 3 and instructions[1]['disasm'].startswith('bl ') and instructions[2]['disasm'].startswith('mov'):
            print('✅  {} {} (match)'.format(hex(mov_instruction['offset']), mov_instruction['code']))
            target = hex(mov_instruction['offset'])
            break
        else:
            print('❌  {} {} (no match)'.format(hex(mov_instruction['offset']), mov_instruction['code']))

    if not target:
        print('❌  Could not find a matching function ...')
        exit(0)

    print('🔥 Seeking to target (s {})...'.format(target))
    r2.cmd('s {}'.format(target))

    fcn_addr = r2.cmd('afi.')
    address = '0x' + fcn_addr.split('.')[-1].strip()

    print('🔥 Found ssl_crypto_x509_session_verify_cert_chain @ {} (afi.)...'.format(address))
    return address

def perform_64bits_analysis_verify_peer_cert(r2, platform):
    print('🔥 Performing Advanced analysis...')
    if platform == 'android':
        r2.cmd('aaaa')
    elif platform == 'ios':
        r2.cmd('aa')

    print('🔥 Searching for instructions with scalar value (/aij {})...'.format(search_scalar_verify_peer_cert))
    search = r2.cmdj('/aij {},'.format(search_scalar_verify_peer_cert))

    mov_instructions = []
    for hit in search:
        if hit['code'].startswith('mov'):
            print('\033[31m{} {}\033[0m'.format(hex(hit['offset']), hit['code']))
            mov_instructions.append(hit)
        else:
            print('{} {}'.format(hex(hit['offset']), hit['code']))

    if not mov_instructions:
        print('❌  Could not find an instruction with {} scalar value...'.format(search_scalar_verify_peer_cert))
        exit(0)

    print('🔥 Performing simple instruction matching to find ssl_verify_peer_cert()...')
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
        print('❌  Could not find a matching function ...')
        exit(0)

    print('🔥 Seeking to target (s {})...'.format(target))
    r2.cmd('s {}'.format(target))

    fcn_addr = r2.cmd('afi.')
    address = '0x' + fcn_addr.split('.')[-1].strip()

    print('🔥 Found ssl_verify_peer_cert @ {} (afi.)...'.format(address))
    return address

def perform_32bits_analysis_verify_cert_chain(r2, platform):
    print('🔥 Performing Advanced analysis...')
    if platform == 'android':
        r2.cmd('aaaa')
    elif platform == 'ios':
        r2.cmd('aa')

    print('🔥 Searching for instructions with scalar value (/aij {})...'.format(search_scalar_verify_cert_chain))
    search = r2.cmdj('/aij {},'.format(search_scalar_verify_cert_chain))

    mov_instructions = []
    for hit in search:
        if hit['code'].startswith('mov'):
            print('\033[31m{} {}\033[0m'.format(hex(hit['offset']), hit['code']))
            mov_instructions.append(hit)
        else:
            print('{} {}'.format(hex(hit['offset']), hit['code']))

    if not mov_instructions:
        print('❌  Could not find an instruction with {} scalar value...'.format(search_scalar_verify_cert_chain))
        exit(0)

    print('🔥 Performing simple instruction matching to find ssl_crypto_x509_session_verify_cert_chain()...')
    target = ''
    for mov_instruction in mov_instructions:
        print('🔥 Find prelude for current offset @ {}'.format(hex(mov_instruction['offset'])))
        r2.cmd('s {}'.format(mov_instruction['offset']))

        prelude = r2.cmd('ap').splitlines()[-1]
        print('🔥 Pattern matching on prelude @ {}'.format(prelude))
        instructions = r2.cmdj('pdj 5 @{}'.format(prelude))
        if len(instructions) == 5 and instructions[0]['type'] == 'push' and instructions[1]['type'] == 'sub'\
                and instructions[2]['type'] == 'mov' and instructions[3]['type'] == 'mov'\
                and instructions[3]['val'] == 0x50 and instructions[4]['type'] == 'store':
            print('✅  scalar offset @ {} -> prelude offset @ {} (match)'.format(mov_instruction['offset'], prelude))
            target = prelude
            break
        else:
            print('❌  scalar offset @ {} -> prelude offset @ {} (no match)'.format(mov_instruction['offset'], prelude))

    if not target:
        print('❌  Could not find a matching function ...')
        exit(0)

    print('🔥 Found ssl_crypto_x509_session_verify_cert_chain @ {} ...'.format(target))
    return hex(int(target, 16) + 1)  # Off by one because it's a THUMB function


def save_to_frida_script(address, platform):
    if platform == 'android':
        with open('template_frida_hook_android.js') as f:
            template = f.read()
    elif platform == 'ios':
        with open('template_frida_hook_ios.js') as f:
            template = f.read()

    output_script = 'frida_flutter_{}_{}.js'.format(platform, time.strftime("%Y.%m.%d"))
    with open(output_script, 'w') as f:
        f.write(template.replace('0x00000000', address))
    print('🔥 Wrote script to {}...'.format(output_script))


if __name__ == "__main__":
    start_time = time.time()

    file = argument_parsing()

    r2 = r2pipe.open(file)
    bits = arch_parsing(r2)
    platform = platform_parsing(r2)

    print('🔥 Detected {} ARM...'.format(platform))
    if platform == 'ios':
        if is_fat_binary(r2, file):
            newfile = thin_binary(file)
            r2 = r2pipe.open(newfile)
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
    print('🚀 exec time: {}s'.format(time.time() - start_time))
