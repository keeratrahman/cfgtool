# cfgtool
# pip install -r requirements.txt
# python cfg_cli.py --hex "55 8b ec 5d c3" --base 0x401000                       # text listing, good for LLMs
# python cfg_cli.py sample.bin --format dot --mode cfg -o submission.dot         # Lab 3 style
# python cfg_cli.py sample.bin --format dot --mode ddg -o submission.dot         # Lab 4 style
# python cfg_cli.py app.exe --format json --sweep                                # 32-bit PE: uses its own base and entry point
# claude mcp add cfg-builder -- python /path/to/cfg_mcp_server.py                # exposes build_cfg / build_cfg_from_file
