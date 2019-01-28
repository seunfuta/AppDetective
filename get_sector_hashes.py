"""
This file builds the application-prediction catalog
to be used to process a test raw .img file to predict past application activity
NOTES:
- requires hashdb v1.0.0 for scan_expanded; hashdb's can be v.1.1.2+

Project Stages:
1. take deltas.dfxml from the "install" slice and build a new dfxml file with only new files [i.e. ignore modified, changed or deleted files]
2.

"""

# for debugging
# import pdb
# pdb.set_trace()
#
import hashlib
import os
import sys
import pprint
import sqlite3
from datetime import datetime
from xml.etree import ElementTree
import xml.etree.cElementTree as ET
import math
import csv
import re
import json

# import xmltodict


DEBUG = True  # turns debug messages on (True) or off (False)


def ramp_trait(bufferin, size):
    # print "buffer", binascii.hexlify(buffer)
    buffer = bytearray(bufferin)
    count = 0;
    for i in range(0, size - 8, 4):
        # note that little endian is detected and big endian is not detected
        # print "buffer[i+0]", buffer[i+0]
        # print "buffer[i+1]", buffer[i+1]
        # print "buffer[i+2]", buffer[i+2]
        # print "buffer[i+3]", buffer[i+3]

        a = (int(buffer[i + 0]) << 0) | (int(buffer[i + 1]) << 8) | (int(buffer[i + 2]) << 16) | (
        int(buffer[i + 3]) << 24)
        b = (int(buffer[i + 4]) << 0) | (int(buffer[i + 5]) << 8) | (int(buffer[i + 6]) << 16) | (
        int(buffer[i + 7]) << 24)
        if (a + 1 == b):
            count += 1
    return count > size / 8


def hist_trait(bufferin, size):
    buffer = bytearray(bufferin)
    hist = {}
    for i in range(0, size - 4, 4):
        a = (buffer[i + 3] << 0) | (buffer[i + 2] << 8) | (buffer[i + 1] << 16) | (buffer[i + 0] << 24)
        if not hist.has_key(a):
            hist[a] = 0
        hist[a] += 1
    if (len(hist) < 3): return True

    for k, v in hist.items():

        if (v > size / 16):
            return True
    return False


def whitespace_trait(buffer, size):
    count = 0
    for i in range(0, size):
        if ((buffer[i]) == 0x20): count += 1
    return count >= (size * 3) / 4


def monotonic_trait(bufferin, size):
    buffer = bytearray(bufferin)
    total = size / 4.0
    increasing = 0
    decreasing = 0
    same = 0
    for i in range(0, size - 8, 4):

        # note that little endian is detected and big endian is not detected
        a = (buffer[i + 0] << 0) | (buffer[i + 1] << 8) | (buffer[i + 2] << 16) | (buffer[i + 3] << 24)
        b = (buffer[i + 4] << 0) | (buffer[i + 5] << 8) | (buffer[i + 6] << 16) | (buffer[i + 7] << 24)
        if (b > a):
            increasing += 1
        elif (b < a):
            decreasing += 1
        else:
            same += 1

    if (increasing / total >= 0.75): return True;
    if (decreasing / total >= 0.75): return True;
    if (same / total >= 0.75): return True;
    return False


def block_label(buffer):
    size = len(buffer)
    # print "size", size
    ss_flags = ""
    if (ramp_trait(buffer, size)):       ss_flags = ss_flags + "R";
    if (hist_trait(buffer, size)):       ss_flags = ss_flags + "H";
    if (whitespace_trait(buffer, size)): ss_flags = ss_flags + "W";
    if (monotonic_trait(buffer, size)):  ss_flags = ss_flags + "M";
    return ss_flags;


def dbg(msg):
    if DEBUG:
        print(str(datetime.now()) + " " + msg)
    else:
        pass


# file_entropy.py
#
# Shannon Entropy of a file
# = minimum average number of bits per character
# required for encoding (compressing) the file
#
# So the theoretical limit (in bytes) for data compression:
# Shannon Entropy of the file * file size (in bytes) / 8
# (Assuming the file is a string of byte-size (UTF-8?) characters
# because if not then the Shannon Entropy value would be different.)
# FB - 201011291

# read the whole file into a byte array
def compute_shannon(bytes512):
    # print "type: ", type(bytes512)
    # print "bytes512", bytes512
    byteArr = map(ord, bytes512)
    fileSize = len(byteArr)
    # print "fileSize: ", fileSize
    # calculate the frequency of each byte value in the file
    freqList = []
    for b in range(256):
        ctr = 0
        for byte in byteArr:
            if byte == b:
                ctr += 1
        freqList.append(float(ctr) / fileSize)
    # Shannon entropy
    ent = 0.0
    for freq in freqList:
        if freq > 0:
            ent = ent + freq * math.log(freq, 2)
    ent = -ent
    return int(ent * 1000)


def get_sector_hash(targetlist):
    offset_filename = []
    for entry in targetlist:
        # string = "null"
        counting = 0
        filename_in_targetlist, dfxml_sourcefile = entry
        tree = ET.ElementTree(file=dfxml_sourcefile)
        # dfxml_h = open(dfxml_sourcefile,'r')
        # dfxmlcontent = dfxml_h.read()
        dfxmlfilelist = []
        newdfxmlfilelist = []
        for element in tree.iter(tag='{http://www.forensicswiki.org/wiki/Category:Digital_Forensics_XML}fileobject'):
            # print type(element.attrib), element.attrib.keys()
            # newfilecount += 1
            line = element.attrib.keys()
            # print type(line), line.__len__()
            # print element
            if line.__len__() == 2:
                # print "line[0]", line[0],"line[1]",line[1]
                if line[0] == '{http://www.forensicswiki.org/wiki/Forensic_Disk_Differencing}changed_file':
                    action = line[1]
                else:
                    action = line[0]
                # action = (element.attrib[line[0]] if

                # print line.__len__(), action[62:]

                for subelem in element:
                    if subelem.tag == "{http://www.forensicswiki.org/wiki/Category:Digital_Forensics_XML}filename":
                        filename = subelem.text
                    if subelem.tag == "{http://www.forensicswiki.org/wiki/Category:Digital_Forensics_XML}inode":
                        inode = subelem.text
                    if subelem.tag == "{http://www.forensicswiki.org/wiki/Category:Digital_Forensics_XML}hashdigest" and \
                                    subelem.attrib['type'] == "md5":
                        md5 = subelem.text
                    if subelem.tag == "{http://www.forensicswiki.org/wiki/Category:Digital_Forensics_XML}byte_runs":
                        for subsubelem in subelem:
                            img_offset = subsubelem.attrib.get('img_offset')
                            if img_offset == None:
                                # print "none image_offset ", element.findall('.//{http://www.forensicswiki.org/wiki/Category:Digital_Forensics_XML}byte_runs')
                                elementrow = element.findall(
                                    './/{http://www.forensicswiki.org/wiki/Category:Digital_Forensics_XML}byte_runs')
                                for elem in elementrow:
                                    for elem2 in elem:
                                        img_offset = elem2.attrib.get('img_offset')
                new_list = [img_offset, filename]
                if not new_list in newdfxmlfilelist: newdfxmlfilelist.append(new_list)
                # print '\n'

            elif line.__len__() == 1:
                action = line[0]
                # print line.__len__(), action[62:]
                for subelem in element:
                    # print subelem.tag
                    if subelem.tag == "{http://www.forensicswiki.org/wiki/Category:Digital_Forensics_XML}filename":
                        filename = subelem.text
                    if subelem.tag == "{http://www.forensicswiki.org/wiki/Category:Digital_Forensics_XML}inode":
                        inode = subelem.text
                    if subelem.tag == "{http://www.forensicswiki.org/wiki/Category:Digital_Forensics_XML}hashdigest" and \
                                    subelem.attrib['type'] == "md5":
                        md5 = subelem.text
                    if subelem.tag == "{http://www.forensicswiki.org/wiki/Category:Digital_Forensics_XML}byte_runs":
                        for subsubelem in subelem:
                            img_offset = subsubelem.attrib.get('img_offset')
                            if img_offset == None:
                                # print "none image_offset ", element.findall('.//{http://www.forensicswiki.org/wiki/Category:Digital_Forensics_XML}byte_runs')
                                elementrow = element.findall(
                                    './/{http://www.forensicswiki.org/wiki/Category:Digital_Forensics_XML}byte_runs')
                                for elem in elementrow:
                                    for elem2 in elem:
                                        img_offset = elem2.attrib.get('img_offset')
                new_list = [img_offset, filename]
                if not new_list in newdfxmlfilelist: newdfxmlfilelist.append(new_list)

            else:
                # print "line[0]", line[0],"line[1]",line[1]
                #if line[0] == '{http://www.forensicswiki.org/wiki/Forensic_Disk_Differencing}changed_file':
                action = line[1]
                #else:
                #action = line[0]
                # action = (element.attrib[line[0]] if

                # print line.__len__(), action[62:]

                for subelem in element:
                    if subelem.tag == "{http://www.forensicswiki.org/wiki/Category:Digital_Forensics_XML}filename":
                        filename = subelem.text
                    if subelem.tag == "{http://www.forensicswiki.org/wiki/Category:Digital_Forensics_XML}inode":
                        inode = subelem.text
                    if subelem.tag == "{http://www.forensicswiki.org/wiki/Category:Digital_Forensics_XML}hashdigest" and \
                                    subelem.attrib['type'] == "md5":
                        md5 = subelem.text
                    if subelem.tag == "{http://www.forensicswiki.org/wiki/Category:Digital_Forensics_XML}byte_runs":
                        for subsubelem in subelem:
                            img_offset = subsubelem.attrib.get('img_offset')
                            if img_offset == None:
                                # print "none image_offset ", element.findall('.//{http://www.forensicswiki.org/wiki/Category:Digital_Forensics_XML}byte_runs')
                                elementrow = element.findall(
                                    './/{http://www.forensicswiki.org/wiki/Category:Digital_Forensics_XML}byte_runs')
                                for elem in elementrow:
                                    for elem2 in elem:
                                        img_offset = elem2.attrib.get('img_offset')
                new_list = [img_offset, filename]
                if not new_list in newdfxmlfilelist: newdfxmlfilelist.append(new_list)

        counting = 0
        imageoffset = 0
        for eachrow in newdfxmlfilelist:
            print eachrow
            if filename_in_targetlist == eachrow[1]:
                # print"filename_in_targetlist ", filename_in_targetlist, " eachrow[1] ", eachrow[1], " eachrow[0] ", eachrow[0]
                counting += 1
                imageoffset = eachrow[0]
                if imageoffset == None:
                    print "***"
                    for element in tree.iter(
                            tag='{http://www.forensicswiki.org/wiki/Category:Digital_Forensics_XML}fileobject'):
                        # string = element.tag
                        for subelem in element:
                            # string = subelem.attrib.keys()
                            if subelem.tag == "{http://www.forensicswiki.org/wiki/Category:Digital_Forensics_XML}filename" and subelem.text == filename_in_targetlist:
                                counting += 1
                                string2 = element.findall(
                                    './/{http://www.forensicswiki.org/wiki/Category:Digital_Forensics_XML}byte_runs')
                                for stringx in string2:
                                    for stringy in stringx:
                                        imageoffset = stringy.attrib.get('img_offset')
                                        # print "imageoffset2 ", imageoffset
                                        # print "string ", string
            else:
                pass

        '''
        for element in tree.iter(tag='{http://www.forensicswiki.org/wiki/Category:Digital_Forensics_XML}fileobject'):
            #string = element.tag
            for subelem in element:
                #string = subelem.attrib.keys()
                if subelem.tag == "{http://www.forensicswiki.org/wiki/Category:Digital_Forensics_XML}filename" and subelem.text == filename_in_targetlist:
                    counting +=1
                    string2 = element.findall('.//{http://www.forensicswiki.org/wiki/Category:Digital_Forensics_XML}byte_runs')
                    for stringx in string2:
                        for stringy in stringx:
                            string = stringy.attrib.get('img_offset')
                    for subelem2 in element:
                        #print subelem2
                        if subelem2.tag and subelem2.tag == "http://www.forensicswiki.org/wiki/Category:Digital_Forensics_XML}byte_runs":
                            print subelem2.tag
                            for sub_sub_elem2 in subelem2:
                                if sub_sub_elem2.attrib == "img_offset":
                                    #image_offset = element.findall('{http://www.forensicswiki.org/wiki/Category:Digital_Forensics_XML}byte_runs')
                                    #string = subelem2.tag.attrib.value
                                    pass
                            break
        '''
        # print "image_offset ", imageoffset, " filename ", filename_in_targetlist, " count ", counting
        offset_filename.append([imageoffset, filename_in_targetlist])
        # print "counting: dfxml", dfxml_sourcefile, " filename ", filename_in_targetlist, " count ", counting, " image_offset ", string


def print_missing_entries(newlist_fileonly, dfxml_file):
    remain = []
    tagged_list = []
    print "newlist length", len(newlist_fileonly)
    tree = ET.ElementTree(file=dfxml_file)
    filename = ""
    inode = ""
    md5 = ""
    # newfilecount = 0
    newdfxmlfilelist = []
    for element in tree.iter(tag='{http://www.forensicswiki.org/wiki/Category:Digital_Forensics_XML}fileobject'):
        # print type(element.attrib), element.attrib.keys()
        # newfilecount += 1
        line = element.attrib.keys()
        # print type(line), line.__len__()
        # print element
        if line.__len__() == 2:
            # print "line[0]", line[0],"line[1]",line[1]
            if line[0] == '{http://www.forensicswiki.org/wiki/Forensic_Disk_Differencing}changed_file':
                action = line[1]
            else:
                action = line[0]
            # action = (element.attrib[line[0]] if

            # print line.__len__(), action[62:]
            for subelem in element:
                if subelem.tag == "{http://www.forensicswiki.org/wiki/Category:Digital_Forensics_XML}filename":
                    filename = subelem.text
                if subelem.tag == "{http://www.forensicswiki.org/wiki/Category:Digital_Forensics_XML}inode":
                    inode = subelem.text
                if subelem.tag == "{http://www.forensicswiki.org/wiki/Category:Digital_Forensics_XML}hashdigest" and \
                                subelem.attrib['type'] == "md5":
                    md5 = subelem.text
            new_list = [action[62:], filename, inode, md5]
            if not new_list[1] in newdfxmlfilelist: newdfxmlfilelist.append(new_list[1])
            # print '\n'

        else:
            action = line[0]
            # print line.__len__(), action[62:]
            for subelem in element:
                # print subelem.tag
                if subelem.tag == "{http://www.forensicswiki.org/wiki/Category:Digital_Forensics_XML}filename":
                    filename = subelem.text
                if subelem.tag == "{http://www.forensicswiki.org/wiki/Category:Digital_Forensics_XML}inode":
                    inode = subelem.text
                if subelem.tag == "{http://www.forensicswiki.org/wiki/Category:Digital_Forensics_XML}hashdigest" and \
                                subelem.attrib['type'] == "md5":
                    md5 = subelem.text
            new_list = [action[62:], filename, inode, md5]
            if not new_list[1] in newdfxmlfilelist: newdfxmlfilelist.append(new_list[1])
    count = 0
    count_there = 0
    for newlist_file in newlist_fileonly:
        if not newlist_file in newdfxmlfilelist:
            count += 1
            remain.append(newlist_file)
        else:
            count_there += 1
            tagged_list.append([newlist_file, dfxml_file])
    print "not found in dfxml ", count, ", and found there in dfxml ", count_there
    return tagged_list, remain
    # for eachone in B2BTlist: print eachone
    # print "newfilecount", newfilecount
    # print newdfxmllist


def process_timediff_deltas_dfxml(dfxml_file):
    tree = ET.ElementTree(file=dfxml_file)
    filename = ""
    inode = ""
    md5 = ""
    img_offset = ""
    newfilecount = 0
    B2BTlist = []
    for element in tree.iter(tag='{http://www.forensicswiki.org/wiki/Category:Digital_Forensics_XML}fileobject'):
        # print type(element.attrib), element.attrib.keys()
        newfilecount += 1
        line = element.attrib.keys()
        # print type(line), line.__len__()
        # print element
        if line.__len__() == 2:
            # print "line[0]", line[0],"line[1]",line[1]
            if line[0] == '{http://www.forensicswiki.org/wiki/Forensic_Disk_Differencing}changed_file':
                action = line[1]
            else:
                action = line[0]
            # action = (element.attrib[line[0]] if
            # new_list = [action[62:], filename, inode, md5, file_run]
            # print line.__len__(), action[62:]
            new_list = []
            breakoutof2loop = False
            for subelem in element:
                if subelem.tag == "{http://www.forensicswiki.org/wiki/Category:Digital_Forensics_XML}filename":
                    filename = subelem.text
                if subelem.tag == "{http://www.forensicswiki.org/wiki/Category:Digital_Forensics_XML}inode":
                    inode = subelem.text
                if subelem.tag == "{http://www.forensicswiki.org/wiki/Category:Digital_Forensics_XML}byte_runs":
                    file_run = []
                    for subsubelem in subelem:
                        # for subsubsubelem in subsubelem:
                        # img_offset = 0
                        if subsubelem.attrib.has_key('type') and subsubelem.attrib['type'] == 'resident':
                            # print "YAHOO!"
                            breakoutof2loop = True
                            break
                        if subsubelem.attrib.has_key('img_offset'):
                            img_offset = subsubelem.attrib.get('img_offset')
                            file_offset = subsubelem.attrib.get('file_offset')
                            if subsubelem.attrib.has_key('uncompressed_len'):
                                length = subsubelem.attrib.get('uncompressed_len')
                            elif subsubelem.attrib.has_key('len'):
                                length = subsubelem.attrib.get('len')
                        else:
                            # img_offset = subsubelem.attrib.get('img_offset')
                            file_offset = subsubelem.attrib.get('file_offset')
                            if subsubelem.attrib.has_key('uncompressed_len'):
                                length = subsubelem.attrib.get('uncompressed_len')
                            elif subsubelem.attrib.has_key('len'):
                                length = subsubelem.attrib.get('len')
                        file_run.append([img_offset, file_offset, length])
                        # print "IMAGE OFFSET!", img_offset
                    if breakoutof2loop:
                        break
                if subelem.tag == "{http://www.forensicswiki.org/wiki/Category:Digital_Forensics_XML}hashdigest" and \
                                subelem.attrib['type'] == "md5":
                    md5 = subelem.text
                    new_list = [action[62:], filename, inode, md5, file_run]  # two tabs left
            if not new_list in B2BTlist: B2BTlist.append([action[62:], filename, inode, md5, file_run])
            # print '\n'

        else:
            action = line[0]
            # print line.__len__(), action[62:]
            # new_list = [action[62:], filename, inode, md5, file_run]
            new_list = []
            breakoutof2loop = False
            for subelem in element:
                # print subelem.tag
                if subelem.tag == "{http://www.forensicswiki.org/wiki/Category:Digital_Forensics_XML}filename":
                    filename = subelem.text
                if subelem.tag == "{http://www.forensicswiki.org/wiki/Category:Digital_Forensics_XML}inode":
                    inode = subelem.text
                if subelem.tag == "{http://www.forensicswiki.org/wiki/Category:Digital_Forensics_XML}byte_runs":
                    file_run = []
                    for subsubelem in subelem:
                        # for subsubsubelem in subsubelem:
                        # img_offset=0
                        if subsubelem.attrib.has_key('type') and subsubelem.attrib['type'] == 'resident':
                            # print "YAHOO!"
                            breakoutof2loop = True
                            break
                        if subsubelem.attrib.has_key('img_offset'):
                            img_offset = subsubelem.attrib.get('img_offset')
                            file_offset = subsubelem.attrib.get('file_offset')
                            # print subsubelem.attrib
                            if subsubelem.attrib.has_key('uncompressed_len'):
                                length = subsubelem.attrib.get('uncompressed_len')
                            elif subsubelem.attrib.has_key('len'):
                                length = subsubelem.attrib.get('len')
                        else:
                            # img_offset = subsubelem.attrib.get('img_offset')
                            file_offset = subsubelem.attrib.get('file_offset')
                            if subsubelem.attrib.has_key('uncompressed_len'):
                                length = subsubelem.attrib.get('uncompressed_len')
                            elif subsubelem.attrib.has_key('len'):
                                length = subsubelem.attrib.get('len')
                        file_run.append([img_offset, file_offset, length])
                    if breakoutof2loop:
                        break
                        # print "IMAGE OFFSET!", img_offset
                if subelem.tag == "{http://www.forensicswiki.org/wiki/Category:Digital_Forensics_XML}hashdigest" and \
                                subelem.attrib['type'] == "md5":
                    md5 = subelem.text
                    new_list = [action[62:], filename, inode, md5, file_run]  ##two tabs left
            if not new_list in B2BTlist: B2BTlist.append(new_list)
            # print '\n'
    # for eachone in B2BTlist: print eachone
    print "newfilecount", newfilecount
    return B2BTlist


def compare2lists(B2BTlistcombo, B2BTAlistcombo):
    B2BTAlist_reduced = []
    # print "common entries"
    common = 0
    dfxml_B2BTlist, B2BTlist = B2BTlistcombo
    print "dfxml_B2BTlist: ", dfxml_B2BTlist
    B2BTl = dfxml_B2BTlist.split("/")
    B2BTn = B2BTl[len(B2BTl) - 1]
    B2BTname = B2BTn.split(".")[0]
    print "B2BTname: ", B2BTname
    dfxml_B2BTAlist, B2BTAlist = B2BTAlistcombo
    print "dfxml_B2BTAlist: ", dfxml_B2BTAlist
    B2BTAl = dfxml_B2BTAlist.split("/")
    B2BTAn = B2BTAl[len(B2BTAl) - 1]
    appname = B2BTAl[len(B2BTAl) - 2]
    B2BTAname = B2BTAn.split(".")[0]
    print "B2BTAname: ", B2BTAname
    filehandle = open(sys.argv[3] + appname + B2BTname + "vs" + B2BTAname + ".txt", 'w')
    filehandle.write("B2BT= " + str(len(B2BTlist)))
    filehandle.write("\n")
    filehandle.write("B2BTA= " + str(len(B2BTAlist)))
    filehandle.write("\n")
    for eachline in B2BTAlist:
        if eachline in B2BTlist:
            print eachline
            if len(eachline) > 0 and (eachline[0] == "new_file" or eachline[0] == "deleted_file"):
                B2BTAlist_reduced.append(eachline)
            common += 1
            # print eachline
        else:
            B2BTAlist_reduced.append(eachline)
            common += 1
    B2BTAlist_reducedcombo = [dfxml_B2BTAlist, B2BTAlist_reduced]
    print "common entries= ", common
    filehandle.write("Common(C)= " + str(common))
    filehandle.write("\n")
    print "unique to B2BTA list", str(len(B2BTAlist_reduced))
    filehandle.write("B2BTAreduced= " + str(len(B2BTAlist_reduced)))
    filehandle.write("\n")
    filehandle.write("Drop in B2BTA= " + str(format(float(common) / len(B2BTAlist), '.2f')))

    counter = 0
    for eachline in B2BTAlist_reduced:
        # print eachline
        counter += 1
        # print eachline
    print "B2BTA_reduced count=", counter
    return B2BTAlist_reducedcombo

def combine2lists(B2BTlistcombo, B2BTAlistcombo):
    B2BTAlist_reduced = []
    B2BTAlist_files = set()
    # print "common entries"
    common = 0
    dfxml_B2BTlist, B2BTlist = B2BTlistcombo
    print "dfxml_B2BTlist: ", dfxml_B2BTlist # e.g. /Volume/SAMSUNG/B_BT.dfxml
    B2BTl = dfxml_B2BTlist.split("/") # e.g. [Volume,SAMSUNG,B_BT.dfxml]
    B2BTn = B2BTl[len(B2BTl) - 1] # e.g. B_BT.dfxml
    B2BTname = B2BTn.split(".")[0] # e.g. B_BT
    print "B2BTname: ", B2BTname
    dfxml_B2BTAlist, B2BTAlist = B2BTAlistcombo
    print "dfxml_B2BTAlist: ", dfxml_B2BTAlist
    B2BTAl = dfxml_B2BTAlist.split("/")
    B2BTAn = B2BTAl[len(B2BTAl) - 1]
    appname = B2BTAl[len(B2BTAl) - 2]
    B2BTAname = B2BTAn.split(".")[0] # e.g. B_BI
    print "B2BTAname: ", B2BTAname
    #filehandle = open(sys.argv[3] + appname + B2BTname + "vs" + B2BTAname + ".txt", 'w')
    #filehandle.write("B2BT= " + str(len(B2BTlist)))
    #filehandle.write("\n")
    #filehandle.write("B2BTA= " + str(len(B2BTAlist)))
    #filehandle.write("\n")
    for eachline in B2BTlist:
        if len(eachline) > 0 and eachline[0] == "new_file" and eachline[3] not in B2BTAlist_files:
            B2BTAlist_reduced.append(eachline)
            B2BTAlist_files.add(eachline[3])
            #common += 1
            # print eachline
    for eachline in B2BTAlist:
        if len(eachline) > 0 and eachline[0] == "new_file" and eachline[3] not in B2BTAlist_files:
            B2BTAlist_reduced.append(eachline)
            B2BTAlist_files.add(eachline[3])
    #noticed there are duplicates in B2BTAlist_reduced
    #B2BTAlist_reduced2 = {}
    #for oldline in B2BTAlist_reduced:
    #if not B2BTAlist_reduced2.has_key(oldline[3]):
    B2BTAlist_reducedcombo = [dfxml_B2BTAlist, B2BTAlist_reduced]
    #print "common entries= ", common
    #filehandle.write("Common(C)= " + str(common))
    #filehandle.write("\n")
    #print "unique to B2BTA list", str(len(B2BTAlist_reduced))
    #filehandle.write("B2BTAreduced= " + str(len(B2BTAlist_reduced)))
    #filehandle.write("\n")
    #filehandle.write("Drop in B2BTA= " + str(format(float(common) / len(B2BTAlist), '.2f')))

    #counter = 0
    #for eachline in B2BTAlist_reduced:
    # print eachline
    #counter += 1
    # print eachline
    print "B2BTA_reduced count=", len(B2BTAlist_reduced)
    return B2BTAlist_reducedcombo

def generate_new_deltas_dfxml():  # old_file):

    tree = ET.ElementTree(
        file='/Volumes/SAMSUNG/OLU/DISKPRINTS/Firefox19-WinXP/234-1/14887-1/234-1-14887-1-10.tar.gz/make_differential_dfxml_prior.sh/deltas.dfxml')
    # print tree
    filename = []
    partition = []
    id = []
    filesize = []
    inode = []
    parent_inode = []
    file_offset = []
    fs_offset = []
    img_offset = []
    len = []
    md5 = []
    sha1 = []
    newfilecount = 0

    for element in tree.iter(tag='{http://www.forensicswiki.org/wiki/Category:Digital_Forensics_XML}fileobject'):
        # print type(element.attrib)
        if element.attrib.has_key('{http://www.forensicswiki.org/wiki/Forensic_Disk_Differencing}new_file'):
            newfilecount = newfilecount + 1
            file_pty_count = 0
            for sub_elem in element:
                # if sub_elem.tag == "{http://www.forensicswiki.org/wiki/Category:Digital_Forensics_XML}parent_object":
                #   for sub_sub_elem2 in sub_elem:
                #      file_pty_count += 1
                #     parent_inode_value = sub_sub_elem2.text
                if sub_elem.tag == "{http://www.forensicswiki.org/wiki/Category:Digital_Forensics_XML}filename":
                    file_pty_count += 1
                    filename_value = sub_elem.text
                if sub_elem.tag == "{http://www.forensicswiki.org/wiki/Category:Digital_Forensics_XML}id":
                    file_pty_count += 1
                    id_value = sub_elem.text
                if sub_elem.tag == "{http://www.forensicswiki.org/wiki/Category:Digital_Forensics_XML}filesize":
                    file_pty_count += 1
                    filesize_value = sub_elem.text
                if sub_elem.tag == "{http://www.forensicswiki.org/wiki/Category:Digital_Forensics_XML}inode":
                    file_pty_count += 1
                    inode_value = sub_elem.text
                if sub_elem.tag == "{http://www.forensicswiki.org/wiki/Category:Digital_Forensics_XML}hashdigest":
                    if sub_elem.attrib['type'] == "md5":
                        file_pty_count += 1
                        md5_value = sub_elem.text
                        # if sub_elem.attrib['type'] =="sha1":
                        #   file_pty_count += 1
                        #  sha1_value = sub_elem.text
                        # print sub_elem.tag
            if file_pty_count == 5:
                filename.append(filename_value)
                id.append(id_value)
                filesize.append(filesize_value)
                inode.append(inode_value)
                md5.append(md5_value)
            else:
                pass

        with open("/Volumes/SAMSUNG/OLU/DUMP/newfile.csv", 'w') as fcsv:
            fieldnames = ['md5', 'filename', 'id', 'filesize', 'inode']
            writer = csv.DictWriter(fcsv, fieldnames=fieldnames, delimiter='\t', quotechar='"')
            writer.writeheader()
            for index in range(0, filename.__len__()):
                writer.writerow(
                    {'md5': md5[index], 'filename': filename[index], 'id': id[index], 'filesize': filesize[index],
                     'inode': inode[index]})
                # print id

    print "filename count " + str(filename.__len__())
    # print "partition count " + str(partition.__len__())
    print "id count " + str(id.__len__())
    print "filesize count " + str(filesize.__len__())
    print "inode count " + str(inode.__len__())
    # print "parent_inode count " + str(parent_inode.__len__())
    # print "file_offset count " + str(file_offset.__len__())
    # print "fs_offset count " + str(fs_offset.__len__())
    # print "img_offset count " + str(img_offset.__len__())
    # print "len count " + str(len.__len__())
    # print "md5 count " + str(md5.__len__())
    # print "sha1 count " + str(sha1.__len__())
    print "new file count " + str(newfilecount)

    # fcsv = open("/Users/sunflower/Downloads/research.csv", 'w')
    # fcsv.write("")


if __name__ == "__main__":
    # need better option handling, help/usage
    # usage: build_catalog.py path-to-deltas.dfxml

    # infile_base=sys.argv[1]

    # print("Building the catalog...")
    startTime = datetime.now()
    print("Processing the DFXML files to extract sector hashes from it....")
    print ("Please enter the filepath to the xml files you wish to have processed...")
    print ("Please be mindful of the order, LIST THEM in do-nothing.dfxml, followed by application-run.dfxml....")
    # print("if there are no more dfxml files to process, press the enter key.....")
    number_of_dfxml = 10  # >raw_input("Please enter the even number of .dfxml files to compare: ")
    file_list = []
    filesystemchange_list = []
    # for count in range(0,int(number_of_dfxml)):
    #    file_list[count] = str(raw_input("Please enter the fullpath of the next .dfxml file: "))
    file_list.append(sys.argv[1] + '/B_BT.dfxml')
    file_list.append(sys.argv[1] + '/B_BI.dfxml')
    file_list.append(sys.argv[1] + '/BI_BIT.dfxml')
    file_list.append(sys.argv[1] + '/BI_BIO.dfxml')
    file_list.append(sys.argv[1] + '/BIO_BIOT.dfxml')
    file_list.append(sys.argv[1] + '/BIO_BIOC.dfxml')
    file_list.append(sys.argv[1] + '/BIOC_BIOCT.dfxml')
    file_list.append(sys.argv[1] + '/BIOC_BIOCU.dfxml')
    file_list.append(sys.argv[1] + '/BIOCU_BIOCUT.dfxml')
    file_list.append(sys.argv[1] + '/BIOCU_BIOCUR.dfxml')
    # print"file_list length ", str(len(file_list))
    for each_elem in range(0, len(file_list)):
        # print "each_elem", str(each_elem)

        # print str(file_list[each_elem])
        filesystemchange_list.append([file_list[each_elem], process_timediff_deltas_dfxml(
            file_list[each_elem])])  # [action[62:], filename, inode, img_offset, md5]
        # B2BTlist = process_timediff_deltas_dfxml(sys.argv[1])  # infile_base+'.dfxml')
        # B2BT = sys.argv[1]
        # print ("B2BT")
        # for elem in B2BTlist:
        #   print elem
        # print ("B2BTA")
        # B2BTAlist = process_timediff_deltas_dfxml(sys.argv[2])
        # B2BTA = sys.argv[2]
        # print ("B2BTA")
        # for elem in B2BTAlist:
        #   print elemdfsdf

    print("Comparing the processed lists in pairs")
    combo_list = []
    for elem_count in range(0, len(filesystemchange_list), 2):
        combo_list.append(combine2lists(filesystemchange_list[elem_count], filesystemchange_list[elem_count + 1]))
    print "len(combo_list)= ", len(combo_list)
    count = 0
    newlist = []
    trashlist = []
    for dfxml_meta in combo_list:
        dfxml_file, action_file_inode_md5_filerun = dfxml_meta
        for eachrow in action_file_inode_md5_filerun:
            # print eachrow
            # print eachrow#####UPDATE MADE BELOW#######
            # if (eachrow[0] == 'new_file') and re.match(r'.*\.\w{2,8}$', eachrow[1], re.M|re.I|re.X):
            if (len(eachrow) > 0) and (eachrow[0] == 'new_file' ) and \
                    re.match(r'.*\.\w{2,8}$', eachrow[1], re.M | re.I | re.X) and not \
                    (re.match(r'^.*Windows\/System32.*$', eachrow[1], re.M | re.I | re.X) or \
                     re.match(r'^.*ProgramData\/Microsoft\/RAC.*$', eachrow[1], re.M | re.I | re.X) or \
                     re.match(r'^.*Windows\/Prefetch.*$', eachrow[1], re.M | re.I | re.X) or \
                     re.match(r'^.*Windows\/ServiceProfiles\/LocalService.*$', eachrow[1], re.M | re.I | re.X) or \
                     re.match(r'^.*Windows\/ServiceProfiles\/NetworkService.*$', eachrow[1], re.M | re.I | re.X) or \
                     re.match(r'^.*Windows\/SoftwareDistribution\/DataStore.*$', eachrow[1], re.M | re.I | re.X) or \
                     re.match(r'^.*Windows\/winsxs.*$', eachrow[1], re.M | re.I | re.X) or \
                     # re.match(r'^.*ProgramData\/Microsoft\/RAC.*$', eachrow[1], re.M | re.I | re.X) or \
                     re.match(r'^.*pagefile.sys.*$', eachrow[1], re.M | re.I | re.X) or \
                     re.match(r'^.*ProgramData\/Microsoft\/Search\/Data\/Applications\/Windows.*$', eachrow[1], re.M | re.I | re.X) or \
                     re.match(r'^.*Windows\/assembly.*$', eachrow[1], re.M | re.I | re.X)):
                newlist.append([dfxml_file] + eachrow) # newlist.append([dxfml_file].extend(eachrow))
            else:
                trashlist.append(eachrow)
            count += 1
    #print "count ", count
    print "newlist", len(newlist)
    # print newlist
    sec_meta = []
    dict = {sys.argv[1] + '/B_BT.dfxml': sys.argv[2] + '/BI.img', \
            sys.argv[1] + '/B_BI.dfxml': sys.argv[2] + '/BI.img', \
            sys.argv[1] + '/BI_BIT.dfxml': sys.argv[2] + '/BIO.img', \
            sys.argv[1] + '/BI_BIO.dfxml': sys.argv[2] + '/BIO.img', \
            sys.argv[1] + '/BIO_BIOT.dfxml': sys.argv[2] + '/BIOC.img', \
            sys.argv[1] + '/BIO_BIOC.dfxml': sys.argv[2] + '/BIOC.img', \
            sys.argv[1] + '/BIOC_BIOCT.dfxml': sys.argv[2] + '/BIOCU.img', \
            sys.argv[1] + '/BIOC_BIOCU.dfxml': sys.argv[2] + '/BIOCU.img', \
            sys.argv[1] + '/BIOCU_BIOCUT.dfxml': sys.argv[2] + '/BIOCUR.img', \
            sys.argv[1] + '/BIOCU_BIOCUR.dfxml': sys.argv[2] + '/BIOCUR.img'}

    block_meta_list = []
    # file_meta_list = []
    filezero_count = {}
    filenonprobative_count = {}
    file_size = {}
    file_name = {}
    # file_meta_dict = {}
    jsonfile = open(sys.argv[3] + sys.argv[4], 'w')
    allfiles = []
    for dfxml_action_file_inode_hash_filerun in newlist:  # [action[62:], filename, inode, md5, file_run] file_run = [img_offset, file_offset, length]
        dfxml, action, file, inode, md5, filerun = dfxml_action_file_inode_hash_filerun
        #if md5 not in
        allfiles.append(md5)
        for imgoffset_fileoffset_len in filerun:
            image_offset, fileoffset, leng = imgoffset_fileoffset_len
            # md5 = "\"" + md5 + "\""
            file_size[md5] = leng
            file_name[md5] = file
            filezero_count[md5] = 0
            filenonprobative_count[md5] = 0

            num_of_sector = int(math.ceil(float(leng) / float(512)))
            # print "number of sectors: ", num_of_sector
            # print "dfxml:", dfxml
            # print "dict[dfxml]: ", dict[dfxml]
            with open(dict[dfxml], 'rb') as fopen:  # dict[dfxml]
                for sector_index in range(0, num_of_sector):
                    block_meta_dict = {}
                    pos = int(image_offset) + int(fileoffset) + (sector_index * 512)
                    m_fileoffset = int(fileoffset) + (sector_index * 512)
                    fopen.seek(pos)
                    fsector = fopen.read(512)
                    hashsec = hashlib.md5(fsector).hexdigest()
                    # print "fsector ", fsector
                    # print "hashsec ", hashsec
                    ##dangerzone?bad idea
                    # for block_meta_dicts in block_meta_list:
                    #    if block_meta_dicts["block_hash"] == hashsec:
                    #        #extend source_offsets
                    #        block_meta_dicts["source_offsets"].extend([md5,1,[m_fileoffset]])

                    # hashsec = "\"" + hashsec + "\""

                    if hashsec == "bf619eac0cdf3f68d496ea9344137e8b":
                        filezero_count[md5] += 1
                        continue

                    if hashsec == "d41d8cd98f00b204e9800998ecf8427e":
                        continue
                    else:
                        block_meta_dict["block_hash"] = hashsec
                        block_meta_dict["source_sub_counts"] = [md5, 1, [m_fileoffset]]
                        entropysec = compute_shannon(fsector)
                        block_meta_dict["k_entropy"] = entropysec
                        blocklabel = block_label(fsector)
                        # blocklabel = "\"" + blocklabel + "\""
                        block_meta_dict["block_label"] = blocklabel
                        if blocklabel != '':
                            filenonprobative_count[md5] += 1
                        # md5 ="\""+md5+"\""
                        # sec_meta.append([dfxml,action,file,md5,image_offset,fileoffset,pos,hashsec])
                        # print dfxml,action,file,md5,image_offset,blocklabel,fileoffset,pos,entropysec, hashsec
                        # block_line = "{\"block_hash\":\""+hashsec+"\",\"k_entropy\":"+str(entropysec)+",\"block_label\":\""+blocklabel+"\",\"source_offsets\":[\""+md5+"\",1,["+str(m_fileoffset)+"]]}"
                        # print block_line
                        # block_meta_dict["source_offsets"] = [md5,1,[int(leng)]]
                        # for block_meta_dicts in block_meta_list:
                        #    if block_meta_dicts["block_hash"]==hashsec:
                        #        #file, md5, blocklabel, m_fileoffset, entropysec, source_offsets = block_meta_dict[hashsec]
                        #        block_meta_dicts["source_offsets"].extend([md5,1,[m_fileoffset]])##fix this'[
                        #        source_offsets = [md5,1,[m_fileoffset]]
                        #        block_meta_dicts["source_offsets"].extend([md5,1,[m_fileoffset]])
                        block_meta_list.append(block_meta_dict)
                        print block_meta_dict
                        jsonfile.write(json.dumps(block_meta_dict, separators=(',', ':')))
                        jsonfile.write("\n")
                        '''

    #with open("/Volumes/Samsung_1TB/VMs/FirefoxWin7x32.json", 'w') as jsonfile:
        #for block_meta_dicts in block_meta_list:
            #print block_meta_dicts
            #jsonfile.write(block_meta_dicts)

    '''
    for file_md5_key in allfiles:
        if file_md5_key == None or not (file_size.has_key(file_md5_key) or filezero_count.has_key(file_md5_key)):
            continue
        newfiledict = {"file_hash": file_md5_key, "filesize": int(file_size[file_md5_key]), "file_type": "",
                       "zero_count": filezero_count[file_md5_key],
                       "nonprobative_count": filenonprobative_count[file_md5_key],
                       "name_pairs": [sys.argv[5], file_name[file_md5_key]]}
        # print newfiledict
        jsonfile.write(json.dumps(newfiledict, separators=(',', ':'), sort_keys=True))
        jsonfile.write("\n")
    '''

    newlist_fileonly = []
    for eachelem in newlist:
        if eachelem[3]== None:
            print eachelem
        if not eachelem[1] in newlist_fileonly:
            newlist_fileonly.append(eachelem[1])
    #print "newlist_fileonly count ", len(newlist_fileonly)
    #for each in newlist:
    #    print each
    #for dfxml_file in dfml_list:
        #get_sector_hashlist(newlist, dfxml_file)
    '''
    '''
    tagged_list1,newlist_fileonly1 = print_missing_entries(newlist_fileonly,'/Volumes/T1/Chrome28-W7x64/B-BI.dfxml')
    tagged_list2,newlist_fileonly2 = print_missing_entries(newlist_fileonly1,'/Volumes/T1/Chrome28-W7x64/B-BT.dfxml')
    tagged_list3,newlist_fileonly3 = print_missing_entries(newlist_fileonly2,'/Volumes/T1/Chrome28-W7x64/BI-BIT.dfxml')
    tagged_list4,newlist_fileonly4 = print_missing_entries(newlist_fileonly3,'/Volumes/T1/Chrome28-W7x64/BI-BIO.dfxml')
    tagged_list5,newlist_fileonly5 = print_missing_entries(newlist_fileonly4,'/Volumes/T1/Chrome28-W7x64/BIO-BIOCT.dfxml')
    tagged_list6,newlist_fileonly6 = print_missing_entries(newlist_fileonly5,'/Volumes/T1/Chrome28-W7x64/BIO-BIOCU.dfxml')
    tagged_list7,newlist_fileonly7 = print_missing_entries(newlist_fileonly6,'/Volumes/T1/Chrome28-W7x64/BIOCU-BIOCUT.dfxml')
    tagged_list8,newlist_fileonly8 = print_missing_entries(newlist_fileonly7,'/Volumes/T1/Chrome28-W7x64/BIOCU-BIOCUR.dfxml')
    taggedlist = tagged_list1+tagged_list2+tagged_list3+tagged_list4+tagged_list5+tagged_list6+tagged_list7+tagged_list8

    sector_hash_list = get_sector_hash(taggedlist)
    '''

    print "#####"
    # for rach in trashlist:
    # print rach

    # with open("/Volumes/Samsung_1TB/VMs/combo_list.txt", 'w') as fileh:
    #   for each_one in combo_list:
    #      fileh.write(str(each_one))


    # build_sector_hashes(new_sector_hashes.db)
    # print("Generating Report on the newly built catalog DB...")
    # comp_dfxml()
    print(datetime.now() - startTime)
    print("Done...")