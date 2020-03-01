import os
import sys
import xmltodict
 

def find_vuln_fixed (list1, list2):

    # compare the Similiarity IDs to see if it was fixed in the latest report

    fixed_list = []

    for element1 in list1:
        found = False
        for element2 in list2:
            if element1['sid'] == element2['sid']:
                found = True
                break
        if found == False:
            fixed_list.append(element1)

    return (fixed_list)


def output_list_of_vuln_fixed(list_fixed):

    # no doubt there is a more efficient way to do this.  hand up for not knowing python lists that well

    # put all the vulnerabilties in a list of just unique name (no duplicates)

    unique_vulns = []
    for i in list_fixed:
        if i['name'] not in unique_vulns:
            unique_vulns.append(i['name'])

    # create a list with a count field and the unique name

    vulnList = []
    for i in unique_vulns:
        vulnElement = {}
        vulnElement['name'] = i
        vulnElement['count'] = 0

        vulnList.append(vulnElement)

    # go through the list and find all the counts of each vulnerabilty fixed

    for i in list_fixed:
        for j in vulnList:
            if i['name'] == j['name']:
                j['count'] += 1

    return (vulnList) 


def print_lists (list_vulns):
    
    f= open("fixed_vulnerabilties.csv","w+")

    f.write ("Vulnerabilty,Issues fixed\n")

    for element in list_vulns:
        f.write (str(element['name']) + "," + str(element['count']) + "\n")

    f.close()

def parse_xml(doc):
    vulnList = []

    if doc and 'CxXMLResults' in doc:
        xml_results = doc['CxXMLResults']

        if xml_results and 'Query' in xml_results:
            for query in xml_results['Query']:
                results = query['Result']
                list_results = []
                if isinstance(results, list):
                    list_results = results
                else:
                    list_results.append(results)
                for result in list_results:

                    path = result['Path']

                    vulnElement = {}

                    vulnElement['name'] = query["@name"]
                    vulnElement['sid'] = path["@SimilarityId"]

                    vulnList.append(vulnElement)

    return ((vulnList))

#-----------------------------------------------------------------------------------------------------

# this script takes in two arguments.  the first one needs to be the earlier XML report, the second one needs to be the latest XML report

args = sys.argv

xml_first = args[1]
xml_second = args[2]

# this will parse the XML files so we can read them

with open(xml_first) as fd:
    document1 = xmltodict.parse(fd.read())

with open(xml_second) as fd:
    document2 = xmltodict.parse(fd.read())

list_output1 = parse_xml(document1)
list_output2 = parse_xml(document2)

# compare the two files and output a list of vulnerabilties fixed

list_of_vuln_fixed = find_vuln_fixed (list_output1, list_output2)

# get the vulnerability name and the count

vuln_list = output_list_of_vuln_fixed(list_of_vuln_fixed)

# print the list out to a csv file

print_lists(vuln_list)
