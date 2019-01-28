import os
import sys
import pprint
import sqlite3
from datetime import datetime
import math
from subprocess import Popen, PIPE
import ast
import subprocess
import json
import ast

matchedblock_json ={}
matchedfile_json = {}
matchedfile2_json = {}
matchedapp_json = {}
matchedapp2_json = {}
matchedapp3_json = {}
matchedapp4_json = {}
ununiq_matchedapp4_json ={}

catalogblock_json ={}
catalogfile_json = {}
catalogfile2_json = {}
catalogapp_json = {}
catalogapp2_json = {}
catalogapp3_json = {}

appcombined_blockcount = {}
appcombined_file2blockcount = {}
appcombined_app2blockcount = {}

block2filemap = {}
file2appmap = {}
block2appmap = {}


with open(sys.argv[2], 'r') as file:
    line_str = file.readlines()
    block_json = {}
    file_json = {}
    app_json = {}
    app2_json ={}
    for line in line_str:
        if line[0]!="#":
            #print type(line) #testing
            line_json = json.loads(line)
            if line_json.has_key("block_hash"):
                #process blocks
                if not block_json.has_key(line_json["block_hash"]):
                    block_json[line_json["block_hash"]] = 1
                elif block_json.has_key(line_json["block_hash"]):
                    block_json[line_json["block_hash"]] += 1
                if not file_json.has_key(line_json["source_sub_counts"][0]):
                    file_json[line_json["source_sub_counts"][0]] = 1
                elif file_json.has_key(line_json["source_sub_counts"][0]):
                    file_json[line_json["source_sub_counts"][0]] += 1

            elif line_json.has_key("file_hash"):
                if file_json.has_key(line_json["file_hash"]):
                    app = line_json["name_pairs"][0]
                    if not app_json.has_key(app):
                        app_json[app] = []
                        app_json[app].append(line_json["file_hash"])

                    elif app_json.has_key(app):
                        if line_json["file_hash"] not in app_json[app]:
                            app_json[app].append(line_json["file_hash"])

appcombined_blockcount = block_json
appcombined_file2blockcount = file_json
appcombined_app2blockcount = app_json



def process_catalog_export(catalog_json):
    with open(catalog_json, 'r') as file:
        line_str = file.readlines()
        block_json  = {}
        file_json = {}
        app_json = {}
        for line in line_str:
            if line[0] != "#":
                line_json = json.loads(line)
                if line_json.has_key("block_hash"):
                    # process blocks
                    file_list = line_json["source_sub_counts"]
                    for index in range(0, len(file_list), 2):
                        if file_list[index] not in file_json.keys():
                            file_json[file_list[index]] = 1
                        else:
                            file_json[file_list[index]] += 1
                elif line_json.has_key("file_hash"):
                    # process files
                    app_list = line_json["name_pairs"]
                    for index in range(0, len(app_list), 2):
                        if app_list[index] not in app_json.keys():
                            app_json[app_list[index]] = file_json[line_json["file_hash"]]
                        else:
                            app_json[app_list[index]] += file_json[line_json["file_hash"]]


def get_matchedrecords(matched_json):
    with open(matched_json, 'r') as file:
        line_str = file.readlines()
        for line in line_str:
            if line[0] != "#":
                imgoffset, blockhash, line_str = line.split('\t')
                line_json = json.loads(line_str)
                if line_json.has_key("block_hash"):
                    # process blocks
                    if not matchedblock_json.has_key(line_json["block_hash"]):
                        matchedblock_json[line_json["block_hash"]] = 1
                        for file_n in line_json["sources"]:
                            if not matchedfile_json.has_key(file_n["file_hash"]):
                                matchedfile_json[file_n["file_hash"]] = 1
                                matchedfile2_json[file_n["file_hash"]] = []
                                matchedfile2_json[file_n["file_hash"]].append(line_json["block_hash"])
                                for indx in range(0,len(file_n["name_pairs"]),2):
                                    if not matchedapp_json.has_key(file_n["name_pairs"][indx]):
                                        matchedapp_json[file_n["name_pairs"][indx]] = 1
                                        matchedapp2_json[file_n["name_pairs"][indx]] = []
                                        matchedapp2_json[file_n["name_pairs"][indx]].append(file_n["file_hash"])
                                    else: #app is already listed
                                        matchedapp_json[file_n["name_pairs"][indx]] += 1
                                        matchedapp2_json[file_n["name_pairs"][indx]].append(file_n["file_hash"])
                            else: #file is already listed
                                matchedfile_json[file_n["file_hash"]] += 1
                                matchedfile2_json[file_n["file_hash"]].append(line_json["block_hash"])
                                # we assume that the file already listed, also has the app already listed
                    #elif matchedblock_json.has_key(line_json["block_hash"]):
                        #matchedblock_json[line_json["block_hash"]] += 1

    for app,filelist in matchedapp2_json.items():
        matchedapp3_json[app] = 0
        matchedapp4_json[app] =[]
        ununiq_matchedapp4_json[app] = []
        for eachfile in filelist:
            #for eachblock in matchedfile2_json[eachfile]:
                #matchedapp3_json[app]+=matchedblock_json[eachblock]

            #matchedapp4_json[app].extend(x for x in matchedfile2_json[eachfile] if x not in matchedapp4_json[app])
            ununiq_matchedapp4_json[app].extend(matchedfile2_json[eachfile])
        matchedapp4_json[app] = {}.fromkeys(ununiq_matchedapp4_json[app]).keys()
        matchedapp3_json[app] = len(matchedapp4_json[app])



def getcatalogrecords():
    with open(sys.argv[2], 'r') as file:
        line_str = file.readlines()
        for line in line_str:
            if line[0] != "#":
                #imgoffset, blockhash, line_str = line.split('\t')
                line_json = json.loads(line)
                if line_json.has_key("block_hash"):
                    # process blocks
                    #if not catalogblock_json.has_key(line_json["block_hash"]):
                    catalogblock_json[line_json["block_hash"]] = 1
                    for file_index in range(0,len(line_json["source_sub_counts"]),2):
                        if not catalogfile_json.has_key(line_json["source_sub_counts"][file_index]):
                            catalogfile_json[line_json["source_sub_counts"][file_index]] = 1
                            catalogfile2_json[line_json["source_sub_counts"][file_index]] = []
                            catalogfile2_json[line_json["source_sub_counts"][file_index]].append(line_json["block_hash"])
                        else:  # file is already listed
                            catalogfile_json[line_json["source_sub_counts"][file_index]] += 1
                            catalogfile2_json[line_json["source_sub_counts"][file_index]].append(line_json["block_hash"])
                if line_json.has_key("file_hash"):
                    if catalogfile_json.has_key(line_json["file_hash"]):
                        for app_index in range(0, len(line_json["name_pairs"]), 2):
                            if not catalogapp_json.has_key(line_json["name_pairs"][app_index]):
                                catalogapp_json[line_json["name_pairs"][app_index]] = 1
                                catalogapp2_json[line_json["name_pairs"][app_index]] = []
                                catalogapp2_json[line_json["name_pairs"][app_index]].append(line_json["file_hash"])
                            else:  # file is already listed
                                catalogapp_json[line_json["name_pairs"][app_index]] += 1
                                catalogapp2_json[line_json["name_pairs"][app_index]].append(line_json["file_hash"])
    for app, file_list in catalogapp2_json.items():
        #print "app", app
        #print "#files", len(catalogapp2_json[app])
        block_cnt = 0
        masterlist = []
        for file in file_list:
            block_cnt += catalogfile_json[file]
            #masterlist.extend( x for x in catalogfile2_json[file] if x not in masterlist)
            masterlist.extend(catalogfile2_json[file])
        uniqmasterlist = {}.fromkeys(masterlist).keys()
        #print "#blocks", block_cnt
        catalogapp3_json[app] = len(uniqmasterlist)#block_cnt

def getblock2appfreq(blockhash):
    p = subprocess.check_output(["hashdb", "scan_hash", "-j", "c", sys.argv[1], blockhash]).splitlines()
    returned_content = p
    # print "returned_content, ", returned_content
    # returned_content = p.communicate()[0]
    # print "returned_content", repr(returned_content)
    #block_count_perfile = 0
    for line in returned_content:
        linejson = json.loads(line)
    return linejson["count"]


def getblockcount(filehash):
    #cmd = 'hashdb hash_table -j o /Volumes/Samsung_1TB/VMs/largeFirefox19-W7x32noOS.hdb ' + filehash + ' > ' + infile_base + '.matches'
    #os.system(cmd)
    p = subprocess.check_output(["hashdb", "hash_table", "-j", "c", sys.argv[1], filehash]).splitlines()

    returned_content = p
    #print "returned_content, ", returned_content
    # returned_content = p.communicate()[0]
    # print "returned_content", repr(returned_content)
    block_count_perfile = 0
    for line in returned_content:
        if line[0] != "#":
            #print "filehash, ", filehash
            #print "line, ", line
            #print str(line)
            blockhash, dictx = line.split('\t')
            #print "dictx #", dictx, "#"
            dict = ast.literal_eval(dictx)
            count = dict["count"]
            block_count_perfile += count
    return (block_count_perfile)

def getblock2appmap2():
    block2filemap = {}
    file2appmap = {}
    block2appmap = {}
    ununiq_block2appmap = {}
    with open(sys.argv[2], 'r') as file:
        line_str = file.readlines()
        file2filesize = {}
        for line in line_str:
            if line[0] != "#":
                line_json = json.loads(line)
                if line_json.has_key("block_hash"):
                    for index in range(0,len(line_json["source_sub_counts"]),2):
                        if not block2filemap.has_key(line_json["block_hash"]):
                            block2filemap[line_json["block_hash"]] = []
                            block2filemap[line_json["block_hash"]].append(line_json["source_sub_counts"][index])
                        else:
                            if line_json["source_sub_counts"][index] not in block2filemap[line_json["block_hash"]]:
                                block2filemap[line_json["block_hash"]].append(line_json["source_sub_counts"][index])
                if line_json.has_key("file_hash"):
                    for index in range(0,len(line_json["name_pairs"]),2):
                        if not file2appmap.has_key(line_json["file_hash"]):
                            file2appmap[line_json["file_hash"]] = []
                            file2appmap[line_json["file_hash"]].append(line_json["name_pairs"][index])
                        else:
                            if line_json["name_pairs"][index] not in file2appmap[line_json["file_hash"]]:
                                file2appmap[line_json["file_hash"]].append(line_json["name_pairs"][index])
        for block,filelist in block2filemap.items():
            block2appmap[block] = []
            ununiq_block2appmap[block] = []
            for file in filelist:
                #block2appmap[block].extend(x for x in file2appmap[file] if x not in block2appmap[block])
                ununiq_block2appmap[block].extend(file2appmap[file])
            block2appmap[block] = {}.fromkeys(ununiq_block2appmap[block]).keys()

    #return block2appmap


def getblock2appmap():
    ununiq_block2appmap = {}
    with open(sys.argv[2], 'r') as file:
        line_str = file.readlines()
        file2filesize = {}
        for line in line_str:
            if line[0] != "#":
                line_json = json.loads(line)
                if line_json.has_key("block_hash"):
                    for index in range(0, len(line_json["source_sub_counts"]), 2):
                        block2filemap[line_json["block_hash"]] = []
                        block2filemap[line_json["block_hash"]].append(line_json["source_sub_counts"][index])
                if line_json.has_key("file_hash"):
                    for index in range(0, len(line_json["name_pairs"]), 2):
                        file2appmap[line_json["file_hash"]] = []
                        file2appmap[line_json["file_hash"]].append(line_json["name_pairs"][index])
    for block, file_list in block2filemap.items():
        ununiq_block2appmap[block] = []
        for eachfile in file_list:
            ununiq_block2appmap[block].extend(file2appmap[eachfile])
        block2appmap[block] = {}.fromkeys(ununiq_block2appmap[block]).keys()




def getfilesizesectorcount():
    with open(sys.argv[2], 'r') as file:
        line_str = file.readlines()
        file2filesize = {}
        for line in line_str:
            if line[0] != "#":
                line_json = json.loads(line)
                if line_json.has_key("file_hash"):
                    # process files
                    filesize = line_json["filesize"]
                    sec_count = int(math.ceil(float(filesize)/float(512)))
                    file2filesize[line_json["file_hash"]] = sec_count
    return file2filesize

def process_matches(matches_file):
    print "processing scan.matched.json"
    #process_catalog_export(sys.argv[1])
    get_matchedrecords(matches_file)
    getcatalogrecords()
    filesizesectorcount = getfilesizesectorcount()
    getblock2appmap()
    print "completed"
    results_list = []
    # (diskprint_id,diskprint_name,total_hashes,total_files)
    # hashes: 7,933,265 total, 3,144,949 unique, 990,158 with freq=1
    # files: 99227? still accurate?
    dpid_list = [
                 ('234-1-14351-1','OfficePro2003-WinXP',catalogapp3_json['OfficePro2003-WinXP'],catalogapp_json['OfficePro2003-WinXP']),#453138,1482), #13931846,7248),#3275826,6309),
                 ('234-1-14887-1','Firefox19-WinXP',catalogapp3_json['Firefox19-WinXP'],catalogapp_json['Firefox19-WinXP']),#792, 25),#690613,122 ),#158305,116),
                 ('234-1-15137-1','Chrome28-WinXP',catalogapp3_json['Chrome28-WinXP'],catalogapp_json['Chrome28-WinXP']),#364401,58), #955355,213 ),#619014,174),
                 ('234-1-15151-1','Safari157-WinXP',catalogapp3_json['Safari157-WinXP'],catalogapp_json['Safari157-WinXP']),#33763,315), #3051061,3522),#604354,1438),
                 ('234-1-15485-1','AdvKeylogger-WinXP',catalogapp3_json['AdvKeylogger-WinXP'],catalogapp_json['AdvKeylogger-WinXP']),#59780, 137), #317661, 228),#154586,209),
                 ('234-1-15487-1','Python264-WinXP',catalogapp3_json['Python264-WinXP'],catalogapp_json['Python264-WinXP']),#48354,2178), #122076,2301 ),#90388,2301),
                 ('234-1-15488-1','TrueCrypt63-WinXP',catalogapp3_json['TrueCrypt63-WinXP'],catalogapp_json['TrueCrypt63-WinXP']),#7186,10), #28367, 20),#9623,19),
                 ('234-1-15489-1','InvSecrets21-WinXP',catalogapp3_json['InvSecrets21-WinXP'],catalogapp_json['InvSecrets21-WinXP']),#14832,63), #347793,193 ),#30464,102),
                 #('234-1-234-1','BaseXPpro-WinXP',2793797,5688), # OS removed
                 #('234-1-4790-1','BaseXPproSP2-WinXP',4780696,9318), # OS removed
                 ('234-1-7959-1','Thunderbird2-WinXP',catalogapp3_json['Thunderbird2-WinXP'],catalogapp_json['Thunderbird2-WinXP']),#26113,137), #128663,177 ),#27772,176),
                 ('9480-1-14351-1','OfficePro2003-W7x32',catalogapp3_json['OfficePro2003-W7x32'],catalogapp_json['OfficePro2003-W7x32']),#1083991, 2601), #12352824,3525 ),#2214045,3440),
                 ('9480-1-14417-1','Wireshark-W7x32',catalogapp3_json['Wireshark-W7x32'],catalogapp_json['Wireshark-W7x32']),#85616,228), #833081, 348),#169994,310),
                 ('9480-1-14782-1','Winzip17pro-W7x32',catalogapp3_json['Winzip17pro-W7x32'],catalogapp_json['Winzip17pro-W7x32']),#369832, 153), #1844942,279 ),#622634,238),
                 ('9480-1-14887-1','Firefox19-W7x32',catalogapp3_json['Firefox19-W7x32'],catalogapp_json['Firefox19-W7x32']),#56235,72), #1550467, 191),#412320,165),
                 ('9480-1-15137-1','Chrome28-W7x32',catalogapp3_json['Chrome28-W7x32'],catalogapp_json['Chrome28-W7x32']),#95091, 107), #1300593, 236),#455989,209),
                 ('9480-1-15141-1','UPX-W7x32',catalogapp3_json['UPX-W7x32'],catalogapp_json['UPX-W7x32']),#1914,7), #104420, 35),#3795,26),
                 ('9480-1-15142-1','sdelete-W7x32',catalogapp3_json['sdelete-W7x32'],catalogapp_json['sdelete-W7x32']),#295,1), #23524,28),#4079,24),
                 ('9480-1-15146-1','eraser-W7x32',catalogapp3_json['eraser-W7x32'],catalogapp_json['eraser-W7x32']),#26863,37), #1034838, 168),#274396,139),
                 ('9480-1-15149-1','Winrar5beta-W7x32',catalogapp3_json['Winrar5beta-W7x32'],catalogapp_json['Winrar5beta-W7x32']),#181288,60), #1689290,177 ),#511171,139),
                 ('9480-1-15150-1','HxD171-W7x32',catalogapp3_json['HxD171-W7x32'],catalogapp_json['HxD171-W7x32']),#3239,8), #18666, 27),#6362,25),
                 ('9480-1-15151-1','Safari157-W7x32',catalogapp3_json['Safari157-W7x32'],catalogapp_json['Safari157-W7x32']),#345228,881), #2405237,1649 ),#566860,1590),
                 ('9480-2-14351-1','OfficePro2003-W7x64',catalogapp3_json['OfficePro2003-W7x64'],catalogapp_json['OfficePro2003-W7x64']),#10234,37), #10613757, 1058),#1712619,1024),
                 ('9480-2-14416-1','Wireshark-W7x64',catalogapp3_json['Wireshark-W7x64'],catalogapp_json['Wireshark-W7x64']),#35621,21), #518703, 340),#162798,318),
                 ('9480-2-14782-1','Winzip17pro-W7x64',catalogapp3_json['Winzip17pro-W7x64'],catalogapp_json['Winzip17pro-W7x64']),#62749,11), #1531965,233),#472837,224),
                 ('9480-2-14887-1','Firefox19-W7x64',catalogapp3_json['Firefox19-W7x64'],catalogapp_json['Firefox19-W7x64']),#173782,74), #1010687, 190),#264404,186),
                 ('9480-2-15137-1','Chrome28-W7x64',catalogapp3_json['Chrome28-W7x64'],catalogapp_json['Chrome28-W7x64']),#162563,25), #453709,68 ),#76295,35),
                 ('9480-2-15141-1','UPX-W7x64',catalogapp3_json['UPX-W7x64'],catalogapp_json['UPX-W7x64']),#7,2),#196446,62 ),#5166,58),
                 ('9480-2-15142-1','sdelete-W7x64',catalogapp3_json['sdelete-W7x64'],catalogapp_json['sdelete-W7x64']),#276,1),#200030,68 ),#11126,66),
                 ('9480-2-15149-1','Winrar5beta-W7x64',catalogapp3_json['Winrar5beta-W7x64'],catalogapp_json['Winrar5beta-W7x64']),#3443,2),#19870, 61),#8737,56),
                 ('9480-2-15151-1','Safari157-W7x64',catalogapp3_json['Safari157-W7x64'],catalogapp_json['Safari157-W7x64'])#2361,41) #2174658,1100 )#375780,1032),
                 #('9480-2-9480-2','Win7x64base-W7x64',29120152,63934) # OS removed
                 ]

    '''
    InvSecrets21-WinXP 63 14832
    Firefox19-WinXP 25 792
    UPX-W7x64 2 7
    sdelete-W7x32 1 295
    Wireshark-W7x64 21 35621
    Winrar5beta-W7x64 2 3443
    Winzip17pro-W7x32 153 369832
    Firefox19-W7x32 72 56235
    Safari157-W7x32 881 345228
    TrueCrypt63-WinXP 10 7186
    Winzip17pro-W7x64 11 62749
    OfficePro2003-WinXP 1482 453138
    Safari157-WinXP 315 33763
    Thunderbird2-WinXP 137 26113
    Python264-WinXP 2178 48354
    Chrome28-W7x32 107 95091
    OfficePro2003-W7x32 2601 1083991
    HxD171-W7x32 8 3239
    UPX-W7x32 7 1914
    Chrome28-WinXP 58 364401
    Firefox19-W7x64 74 173782
    Winrar5beta-W7x32 60 181288
    sdelete-W7x64 1 276
    Wireshark-W7x32 228 85616
    AdvKeylogger-WinXP 137 59780
    eraser-W7x32 37 26863
    OfficePro2003-W7x64 37 10234
    Safari157-W7x64 41 2361
    Chrome28-W7x64 25 162563
    '''
    print "apps", len(matchedapp_json)
    print "files", len(matchedfile_json)
    print "blocks", len(matchedblock_json)
    for dpid,dpname,total_hashes,total_files in dpid_list:

        print("Processing DPID: "+dpid+" "+dpname)
        ### temp hack follows to speed up file-only processing
        hashes_found=0
        hashes_found_weighted=0.0
        hashes_total_weighted = 0.0
        #pi = Popen(["hashdb", "size", "/Volumes/Samsung_1TB/VMs/largeFirefox19-W7x32noOS.hdb"], stdout=PIPE, stderr=PIPE, stdin=PIPE)
        #hashdbstory = pi.stdout.read()
        #total_files = hashdbstory["hash_store"]
        ### end temp hack; remember to uncomment blocks below for hash computations...
        blockhashlist = [] #list of block hashes
        blockhashfreq = {}  # blockhash:freq
        filehashlist = []
        fileimageoffsetrun = {}  # filehash:[img_offset1,img_offset2,...]
        # filehashblock = {} #filehash:[blockhash1, blockhash2,...]
        block2filehashmap = {}
        filehashfreq = {}
        fileblockcount = {}
        block_counter = 0
        block_weighted_summation = 0.0
        file_counter = 0
        file_weighted_summation = 0.0
        # basic hashes method
        print("starting basic hashes method")
        #with open(matches_file,'r') as jsonhandle:
        counting = 0

        if matchedapp_json.has_key(dpname):
            hashes_found = matchedapp3_json[dpname]
        print "hashes_found", hashes_found

        #approach 1 inaccurate
        '''
        if matchedapp2_json.has_key(dpname):
            for file in matchedapp2_json[dpname]:
                for block in matchedfile2_json[file]:
                    #print"block", block
                    #print "matchedblock_json[block]", matchedblock_json[block]
                    #print "appcombined_blockcount[block]", appcombined_blockcount[block]
                    hashes_found_weighted += float(int(matchedblock_json[block]))/float(int(appcombined_blockcount[block]))
        '''
        # approach 2 accurate
        #for blockn, freqn in matchedblock_json.items():
            #print "blockn", blockn
            #print "hashes_found_weighted",hashes_found_weighted
            #print "freqn",freqn
            #block2appfreq = len(block2appmap[blockn])
            #print "block2appfreq", block2appfreq

            #hashes_found_weighted += float(int(1)) / float(int(block2appfreq)) #replaced freqn with 1
        #hashes_found_weighted = (float(hashes_found_weighted) / float(hashes_found)) * float(100)
        masterblocklist = []
        ununiq_masterblocklist = []
        if matchedapp2_json.has_key(dpname):
            for file in matchedapp2_json[dpname]:
                #masterblocklist.extend(x for x in matchedfile2_json[file] if x not in masterblocklist)
                ununiq_masterblocklist.extend(matchedfile2_json[file])
            masterblocklist = {}.fromkeys(ununiq_masterblocklist).keys()

            for blockn in masterblocklist:
                hashes_found_weighted += float(1)/float(len(block2appmap[blockn]))

        mastersectorlist = []
        ununiq_mastersectorlist = []
        if catalogapp2_json.has_key(dpname):
            for file in catalogapp2_json[dpname]:
                #mastersectorlist.extend(x for x in catalogfile2_json[file] if x not in mastersectorlist)
                ununiq_mastersectorlist.extend(catalogfile2_json[file])
            mastersectorlist = {}.fromkeys(ununiq_mastersectorlist).keys()

        for sectorn in mastersectorlist:
            hashes_total_weighted += float(1) / float(len(block2appmap[sectorn]))


        print "hashes_found_weighted", hashes_found_weighted
        files_found = 0
        if matchedapp2_json.has_key(dpname):
            files_found = len(matchedapp2_json[dpname])
        print "files_found", files_found
        files_found_weighted = 0.0 #ff
        if matchedapp2_json.has_key(dpname):
            for filex in matchedapp2_json[dpname]:
                files_found_weighted += float(len(matchedfile2_json[filex]))/float(len(catalogfile2_json[filex]))#float(filesizesectorcount[filex])
        print "files_found_weighted", files_found_weighted

        total_files_weighted = 0.0
        for filen in catalogapp2_json[dpname]:
            total_files_weighted += float(1)/float(len(file2appmap[filen]))

        combined_weighted = 0.0
        tf=0.0
        idf=0.0
        tf_idf=0.0
        '''
        if(total_hashes==0):
                tf = 0.0
        else:
                tf = ( hashes_found / total_hashes )
        if(files_found==0):
                idf = 0.0
        else:
                idf = math.log( total_files / files_found )
        tf_idf = tf * idf
        '''

        # simple computations and write to list
        results_list.append([dpid,dpname,hashes_found,total_hashes,(float(hashes_found)/float(total_hashes)*100),(float(hashes_found_weighted)/float(hashes_total_weighted)*100),files_found,total_files,(float(files_found)/float(total_files)*100),(float(files_found_weighted)/float(total_files_weighted)*100),combined_weighted,tf_idf])
    # output results
    print("\nSource Image: ")
    print("\nResults:")
    print("{0:<18} {1:<25} {2:>10} {3:>10} {4:>7} {5:>7} {6:>10} {7:>10} {8:>7} {9:>7} {10:>7} {11:>10}".format('diskprintID','diskprintName', 'sectors_found', 'sectors_total', 'sector%', 'w_sector%', 'files_found', 'files_total', 'file%', 'w_file%', 'w_combined%', 'tf_idf'))
    results_list.sort(key=lambda tup: tup[9], reverse=True) # sort by w_file%
    for (x0,x1,x2,x3,x4,x5,x6,x7,x8,x9,x10,x11) in results_list: print("{0:<18} {1:<25} {2:>13d} {3:>13d} {4:>6.2f}% {5:>8.2f}% {6:>11d} {7:>11d} {8:>6.2f}% {9:>6.2f}% {10:>10.2f}% {11:>10.2f}   ".format(x0,x1,x2,x3,x4,x5,x6,x7,x8,x9,x10,x11))

if __name__ == "__main__":
    process_matches(sys.argv[3]) #sys.argv[1]