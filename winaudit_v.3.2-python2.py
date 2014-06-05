import os, datetime, sys, re
import xml.etree.ElementTree as ET


num_files_scanned = 0 # Variable to keep track of files scanned
error_files = []
csv_delim = ","
file_extension = ".csv"


def main(argv):
    global csv_delim
    # Welcome banner
    print '*==============================================================================*'
    print '* WinAudit.py - v3.2                                                           *'
    print '* For the most up to date version visit https://github.com/scott-be/winaudit   *'
    print '* Happy Hacking!                                                               *'
    print '*==============================================================================*'

    # Get the file path if no file path is provided as a argument
    folderpath = raw_input('Enter a file path: ').strip().replace('"','') if len(argv) == 1 else argv[1]
    
    # Output network info?
    direction = ''
    while direction.strip().lower() != 'n' and direction.strip().lower() != 'y':
        direction = raw_input('Output network information [y/N]')
        if not direction:
            break


    # Put in the print function of the WinAudit Class
            # Create output folder if it does not exists...
            if not os.path.exists('output'):
                os.makedirs('output') # Create an output dir

            # Saves the file as the current datetime + _output in the output dir
            time_now        = datetime.datetime.now().strftime("%Y-%m-%d-%I.%M.%S")
            output_filename = 'output' + os.sep + time_now + '_output' + file_extension 
            output_file     = open(output_filename,'w')
            # Heading
            output_file.write('Location'+ csv_delim +
                              'Date of WinAudit'+ csv_delim +
                              'Computer Name'+ csv_delim +
                              # 'Computer Type'+ csv_delim +
                              'OS Version'+ csv_delim +
                              'AutoLogon Enabled'+ csv_delim +
                              'Screen Saver Enabled'+ csv_delim +
                              'Screen Saver Timeout'+ csv_delim +
                              'Screen Saver Password Protected'+ csv_delim +
                              'Force Network Logoff'+ csv_delim +
                              'Minimum Password Length'+ csv_delim +
                              'Maximum Password Age'+ csv_delim +
                              'Historical Passwords'+ csv_delim +
                              'Lockout Threshold'+ csv_delim +
                              'Encryption'+ csv_delim +
                              'Unique User ID'+ csv_delim +
                              'Last Installed Security Update' + csv_delim +
                              # _info
                              'Location'+ csv_delim +
                              'Computer Name' + csv_delim +
                              'Username' + csv_delim +
                              'IP Address' + csv_delim +
                              'Computer Type' + csv_delim +
                              'Encryption' + csv_delim +
                              'Encryption Software' + csv_delim +
                              'HDD Encrypted?' + csv_delim +
                              'USB Encrypted?' + csv_delim +
                              'AV?' + csv_delim +
                              'AV Name' + csv_delim +
                              'AV Date' + csv_delim +
                              'Windows Update Date' + csv_delim +
                              'Notes' + '\n')

    # Look for _winaudit.xml and _info.xml files and save into dictionary
    for root, dirs, files in os.walk(folderpath):
        path = root.split(os.sep)
        xml_files = {}

        # Save the found file into the dictionary
        for file in files:
            if file.endswith('_winaudit.xml'):
                xml_files['winaudit'] = file
            if file.endswith('_info.xml'):
                xml_files['info'] = file

        # Call output funtions and save in output var
        winaudit_output = ''
        info_output = ''
        if not direction or direction.strip().lower() == 'n':
            if 'winaudit' in xml_files:
                winaudit_output = output_general_info(root + os.sep + xml_files['winaudit'])
                # Only look for the _info file if we have a winaudit for it
                if 'info' in xml_files:
                    # pass # TODO
                    info_output = get_info(root + os.sep + xml_files['info'])

                # Write output vars to file
                output_file.write(winaudit_output + csv_delim + info_output + '\n')
        else:
            output_network_info(folderpath)

    output_file.close()
#        percent_complete = round(((float(num_files_scanned)/(len(winaudit_files)))*100.0), 2)
    print '===================' 
    print '[Complete]' 
    print 'Output file: ' + output_filename 
#       print 'Scanned ' + str(num_files_scanned) + ' out of ' + str(len(winaudit_files)) + ' WinAudit files. (' + str(percent_complete) + '%)'
    if error_files:
        print '\n***The following files had errors and could not be recovered:***'
        for f in error_files:
            print f
    print '===================' 
    
    # Transpose file?
    # TODO - Move to its own function
    transpose = ''
    while transpose.strip().lower() != 'n' and transpose.strip().lower() != 'y':
        transpose = raw_input('Output vertical? [y/N]')
        if not transpose:
            break
    if transpose.strip().lower() == 'y':
        # transpose_file(output_filename)
        # TODO fix transpose
        print "not working just yet... :/"

    # Done and exit
    print '==================='
    raw_input('Press any key to exit')
    
def output_general_info(filename):
    global num_files_scanned # Variable to keep track of files scanned
    global error_files
    while True:
        try:
            # Init line var
                line  = ''

            # Make a tree from the xml file
                tree = ET.parse(filename)

            # Pull - Computer Name
                computer_name = tree.find("./category[@title='System Overview']/subcategory/recordset/datarow[1]/fieldvalue[2]").text
                computer_name = computer_name.upper()
                
            # Pull - Location (takes the filename and removes any slashes, the computer name and the .xml extension)
                # TODO get location from _info
                location = 'TODO'

            # Pull - Date Scanned from the xml file (via RegEx)
                title  = tree.find('./title').text
                m  = re.search('(\d{1,2}/\d{1,2}/\d{4})', title)
                if m:
                    date_created = m.group(1)
                else:
                    date_created = 'Unknown'
                
            # Add - Location, Date Scanned, Computer Name
                line += location + ' ' + csv_delim
                line += date_created + csv_delim
                line += computer_name + csv_delim

            # # Determine the computer type
            #     if computer_name[0].upper() == 'W':
            #         computer_type = 'Workstation'
            #     elif computer_name[0].upper() == 'L':
            #         computer_type = 'Laptop'
            #     else:
            #         computer_type = 'Unknown'
            #     line += computer_type + csv_delim

            # Get OS Ver
                os_ver  = tree.find("./category[@title='System Overview']/subcategory/recordset/datarow[6]/fieldvalue[2]").text
                line += os_ver + csv_delim

            # Pull & Add - Security Settings
                for child in tree.findall("./category[@title='Security']/subcategory[@title='Security Settings']/recordset/datarow"):
                    if child[0].text in {"AutoLogon", "Screen Saver", "All Accounts"}:
                        line += child[2].text + csv_delim

            # Placeholder for encryption feild
                line += '-' + csv_delim

            # Pull & Add Username (only if the username is different from the computer name)
                username = tree.find("./category[@title='System Overview']/subcategory/recordset/datarow[17]/fieldvalue[2]").text
                # username = '' if username.upper() == computer_name.upper() else username
                line += username + csv_delim

            # Get last installed update 
                updates = tree.find("./category[@title='Installed Software']/subcategory[@title='Software Updates']/recordset")
                line += str(getLatestUpdate(updates))

            # Done
                print '[Done] -', computer_name

            # Return line
                num_files_scanned += 1
                return line
            
        except Exception as e:
            print '[Error] - "' + os.path.basename(filename) + '"'

            # If the error is because of a control character that cannot be parsed - Attempt to fix
            # TODO prevent any infinite loops
            if re.search('^not well-formed \(invalid token\): line ', str(e)):
                print '\tAttempting to fix...'
                linenum = re.search('^not well-formed \(invalid token\): line (\d*)', str(e)).group(1)
                remove_line(filename, linenum)
                continue
            else:
                error_files.append(os.path.basename(filename))
                print e
                break

def output_network_info(folderpath):
    print 'output network info...'
    # Create output folder if it does not exists...
    if not os.path.exists('output'):
        os.makedirs('output') # Create an output dir

    # Saves the file as the current datetime + _output in the output dir
    time_now        = datetime.datetime.now().strftime("%Y-%m-%d-%I.%M.%S")
    output_filename = 'output' + os.sep + time_now + '_network_output' + file_extension
    output_file     = open(output_filename,'w')

    # Heading
    output_file.write('Computer Name'+ csv_delim +
                      'Computer Location'+ csv_delim +
                      'Interface Name(s)'+ csv_delim +
                      'IP Address'+ csv_delim +
                      'DHCP Server'+ csv_delim +
                      'MAC Address\n')

    # Recursivly find all .xml files in the file path
    winaudit_files = [os.path.join(dirpath, f)
        for dirpath, dirnames, files in os.walk(folderpath)
        for f in files if f.endswith('.xml')]

    # Loop through the files
    num_files_scanned = 0 # Variable to keep track of errors
    error_files = []
    for filename in winaudit_files:
        while True:
            try:
                    line  = ''

                # Make a tree from the xml file
                    tree = ET.parse(filename)

                # Pull the computer name
                    computer_name = tree.find("./category[@title='System Overview']/subcategory/recordset/datarow[1]/fieldvalue[2]").text
                    computer_name = computer_name.upper()
                    line += computer_name + csv_delim

                # Pull - Location (takes the filename and removes any slashes, the computer name and the .xml extension)
                    location = re.sub(r'^(.*[\\\/])', '', filename).replace(computer_name,'').replace(computer_name.lower(),'').replace('.xml','')
                    location = re.sub(r'^ * - *', '', location).replace('-','')
                    location = re.sub(r'^_', '', location)
                    location = location.strip()
                    if not location:
                        location = '-'
                    line += location + csv_delim

                # Pull IP Address, MAC address, DHCP Server from all network interfaces
                    interfaces = tree.find("./category[@title='Network TCP/IP']").getchildren()
                    for i, interface in enumerate(interfaces):

                        interface_name = interface.get('title')
                        ip_address = interface.find('recordset/datarow[10]/fieldvalue[2]').text
                        dhcp_server = interface.find('recordset/datarow[9]/fieldvalue[2]').text
                        mac_address = interface.find('recordset/datarow[16]/fieldvalue[2]').text

                        if ip_address == None:   # look to see if the IP address was found
                            ip_address = "None"
                        if dhcp_server == None:  # look to see if DHCP Server was found
                            dhcp_server = "None"
                        if mac_address == None:  # look to see if a MAC was found
                            mac_address = "None"

                        line += interface_name + csv_delim
                        line += ip_address + csv_delim
                        line += dhcp_server + csv_delim
                        line += mac_address + csv_delim

                        if i == len(interfaces)-1: # Look to see if its the last interface and insert a newline
                            line += '\n'

                # Done
                    print '[Done] -', computer_name

                # Write line to file
                    output_file.write(line)
                    num_files_scanned += 1
                    break

            except Exception as e:
                print '[Error] - "' + os.path.basename(filename) + '"'

                # If the error is because of a control character that cannot be parsed - Attempt to fix
                # TODO prevent any infinite loops
                if re.search('^not well-formed \(invalid token\): line ', str(e)):
                    print '\tAttempting to fix...'
                    linenum = re.search('^not well-formed \(invalid token\): line (\d*)', str(e)).group(1)
                    remove_line(filename, linenum)
                    continue
                else:
                    error_files.append(os.path.basename(filename))
                    print e
                    break

    # Done and exit
    output_file.close()
    percent_complete = round(((float(num_files_scanned)/(len(winaudit_files)))*100.0), 2)
    print '===================' 
    print '[Complete]' 
    print 'Output file: ' + output_filename 
    print 'Scanned ' + str(num_files_scanned) + ' out of ' + str(len(winaudit_files)) + ' WinAudit files. Thats ' + str(percent_complete) + '%!'
    if error_files:
        print '\n***The following files had errors and could not be recovered:***'
        for f in error_files:
            print f
    print '==================='
    raw_input('Press any key to exit')

def getLatestUpdate(tree):
  date_list = [] # Used to store list of dates
  for recordset in tree:
    if str(recordset.tag) == "datarow":
      update_description = recordset.find("fieldvalue[3]").text # Store update description
      update_date = recordset.find("fieldvalue[2]").text # Store installed on date
      
      # Match only security updates descriptions
      if re.match(r'(Security Update$)|(Security Update for Windows XP(.*))|(Security Update for Windows 7(.*))|(Security Update for Windows Server 2003(.*))', str(update_description), re.IGNORECASE):
        if update_date is not None:
            if '-' in update_date:
                date_list.append(datetime.datetime.strptime(update_date, '%Y-%m-').date())
            elif '/' in update_date:
                date_list.append(datetime.datetime.strptime(update_date, '%m/%d/%Y').date())
            else:
                return 'error'

  # Sort list of dates
  date_list = sorted(date_list)

  # return latest date (last element)
  return str(date_list[-1])

def get_info(filename):
    tree = ET.parse(filename)
    site_name = tree.find("./siteName").text
    global csv_delim
    line = ''

    # Pull Location
    line += tree.find("./location").text + csv_delim

    # Pull Computer Name
    line += tree.find("./computerName").text.upper() + csv_delim

    # Pull Username
    line += tree.find("./userName").text + csv_delim

    # Pull IP Address
    line += tree.find("./ipAddress").text + csv_delim

    # Pull Computer Type
    line += tree.find("./computerType").text + csv_delim

    # Pull Encryption
    line += tree.find("./encryption").text + csv_delim

    # Pull Encryption Software
    line += str(tree.find("./encryptionName").text) + csv_delim

    # Pull HDD Encrypted?
    line += tree.find("./hddEncryption").text + csv_delim

    # Pull USB Encrypted?
    line += tree.find("./usbEncryption").text + csv_delim

    # Pull AV?
    line += tree.find("./antivirus").text + csv_delim

    # Pull AV Name
    line += tree.find("./antivirusName").text + csv_delim

    # Pull AV Date
    line += tree.find("./antivirusDate").text + csv_delim

    # Pull Windows Update Date
    line += tree.find("./windowsupdateDate").text

    # Pull Notes
    if tree.find("./notes").text:
        line += csv_delim + tree.find("./notes").text.replace(',', '')

    return line

def transpose_file(output_filename):
    print 'Transposing file...',
    
    with open(output_filename, 'r') as f:
        lis = [x.strip().split(csv_delim) for x in f]

    output_file = open(output_filename, 'w') # Have to open the file back up
    line = ''
    for x in zip(*lis):
        for y in x:
            line += y + csv_delim
        line += '\n'
    output_file.write(line)
    output_file.close
    print '[Done]'

def remove_line(file_name, line_num):
    line_num = int(line_num) - 1
    lines = open(file_name, 'r').readlines()
    lines[line_num] = '\n'
    out = open(file_name, 'w')
    out.writelines(lines)
    out.close()

if __name__ == "__main__":
    main(sys.argv) 
