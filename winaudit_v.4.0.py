import os, datetime, sys, re
import xml.etree.ElementTree as ET

def main(argv):

    # Welcome banner
    print '*===========================================================*'
    print '* WinAudit.py - v4.0                                        *'
    print '* Fork me on GitHub! - https://github.com/scott-be/winaudit *'
    print '* Happy Hacking!                                            *'
    print '*===========================================================*'

    # Get the file path if no file path is provided as an argument
    folderpath = raw_input('Enter a file path: ').strip().replace('"','') if len(argv) == 1 else argv[1]
    filename = ''

    # Create output folder if it does not exists...
    if not os.path.exists('output'):
        os.makedirs('output') # Create an output dir

    # Saves the file as the current datetime + _output in the output dir
    time_now        = datetime.datetime.now().strftime("%Y-%m-%d-%I.%M.%S")
    # output_filename = 'output' + os.sep + time_now + '_output.csv'
    output_filename = 'out.csv'
    output_file     = open(output_filename,'w')

    write_header(output_file)

    # Look for _winaudit.xml and _info.xml files and save into dictionary
    for root, dirs, files in os.walk(folderpath):
        if root == folderpath: continue # Skip the root folder

        xml_files = {'winaudit' : None, 'info' : None} # Used to save a two element dictionary containing the _winaudit and _info files
        
        for file in files: # Look for the two files (_winaudit and _info) and save them to the xml_files dictionary
            if file.endswith('.xml'):
                if file.endswith('_winaudit.xml'):
                    xml_files['winaudit'] = root + os.sep + file
                if file.endswith('_info.xml'):
                    xml_files['info'] = root + os.sep + file

    output_file.close() # Close file

                scan = WinAudit(xml_files['winaudit'], xml_files['info']) # create a new WinAudit object and pass it the _winaudit and _info files
                scan.audit() # parse the files
                scan.print_variables() # print the files
                scan.write(output_filename)
def write_header(output_file):
    for k in WinAudit.ORDER:
        output_file.write(k + ',')
    output_file.write('\n')

class WinAudit(object):
        ORDER = (
            'Scan Date',
            'Location',
            'Computer Name',
            'Computer Type',
            'OS Version',
            'Autologon Enabled',
            'Screensaver Enabled',
            'Screensaver Timeout',
            'Screensaver Password',
            'Network Logoff',
            'Minimum Password Length',
            'Maximum Password Age',
            'Historical Passwords',
            'Lockout Threshold',
            'Encrtption Software',
            'Hard Drive Encryption',
            'USB Encryption',
            'User ID',
            'Antivirus Software',
            'Antivirus Definition Date',
            'Windows Update',
            'IP Address',
            'Notes'
        )

        def __init__(self, winaudit = None, info = None):
            self._winaudit = winaudit
            self._info = info
            self.variables = {
                'Scan Date'                 : '',
                'Location'                  : '',
                'Computer Name'             : '',
                'Computer Type'             : '',
                'OS Version'                : '',
                'Autologon Enabled'         : '',
                'Screensaver Enabled'       : '',
                'Screensaver Timeout'       : '',
                'Screensaver Password'      : '',
                'Network Logoff'            : '',
                'Minimum Password Length'   : '',
                'Maximum Password Age'      : '',
                'Historical Passwords'      : '',
                'Lockout Threshold'         : '',
                'Encrtption Software'       : '',
                'Hard Drive Encryption'     : '',
                'USB Encryption'            : '',
                'User ID'                   : '',
                'Antivirus Software'        : '',
                'Antivirus Definition Date' : '',
                'Windows Update'            : '',
                'IP Address'                : '',
                'Notes'                     : ''
            }

        def set_variable(self, k, v):
            self.variables[k] = v;

        def get_variable(self, k):
            return self.variables.get(k, None)

        def print_variables(self):
            print '~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~='
            f = open('out.txt', 'w')
            for k in order:
                print k + '\t' + self.get_variable(k)
                f.write(k + ',' + self.get_variable(k))
                
            f.write('\n')
            f.close()

        def write(self, f):
            for k in self.ORDER:
                f.write(self.get_variable(k) + ',')
            f.write('\n')

        def audit(self):
            # Parse winaudit.xml
                while True and self._winaudit != None:
                    try:
                        # Make a winaudit_tree from the xml file
                            winaudit_tree = ET.parse(self._winaudit)

                        # Pull - Computer Name
                            self.set_variable('Computer Name', winaudit_tree.find("./category[@title='System Overview']/subcategory/recordset/datarow[1]/fieldvalue[2]").text.upper())
                            
                        # Pull - Date Scanned from the xml file (via RegEx)
                            title  = winaudit_tree.find('./title').text
                            m  = re.search('(\d{1,2}/\d{1,2}/\d{4})', title)
                            if m:
                                self.set_variable('Scan Date', m.group(1))
                            else:
                                self.set_variable('Scan Date', 'Unknown')

                        # Get OS Version
                            self.set_variable('OS Version', winaudit_tree.find("./category[@title='System Overview']/subcategory/recordset/datarow[6]/fieldvalue[2]").text)

                        # Pull & Add - Security Settings
                            security_settings = winaudit_tree.find("./category[@title='Security']/subcategory[@title='Security Settings']/recordset")
                            self.set_variable('Autologon Enabled', security_settings[3][2].text)
                            self.set_variable('Screensaver Enabled', security_settings[4][2].text)
                            self.set_variable('Screensaver Timeout', security_settings[5][2].text)
                            self.set_variable('Screensaver Password', security_settings[6][2].text)
                            self.set_variable('Network Logoff', security_settings[7][2].text)
                            self.set_variable('Minimum Password Length', security_settings[8][2].text)
                            self.set_variable('Maximum Password Age', security_settings[9][2].text)
                            self.set_variable('Historical Passwords', security_settings[10][2].text)
                            self.set_variable('Lockout Threshold', security_settings[11][2].text)

                        # Pull & Add Username
                            self.set_variable('User ID', winaudit_tree.find("./category[@title='System Overview']/subcategory/recordset/datarow[17]/fieldvalue[2]").text)

                        # Get last installed update
                            update_tree = winaudit_tree.find("./category[@title='Installed Software']/subcategory[@title='Software Updates']/recordset")
                            date_list = [] # Used to store list of dates
                            for recordset in update_tree:
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
                                            self.variables['Windows Update'] = 'error'

                            # Sort list of dates
                            date_list = sorted(date_list)

                            # return latest date (last element)
                            self.variables['Windows Update'] = str(date_list[-1])

                        # Get IP address
                            interfaces = winaudit_tree.find("./category[@title='Network TCP/IP']").getchildren() # get a list of interfaces

                            for i, interface in enumerate(interfaces): # loop through all the interfaces
                                ip_address = interface.find('recordset/datarow[10]/fieldvalue[2]').text

                                # set ip_address to an empty string if ip_address is NoneType
                                if ip_address == None:
                                    ip_address = ''

                                # look to see if the IP found is a real IP address and break
                                if re.match(r'(?:\d{1,3}\.){3}\d{1,3}', ip_address):
                                    self.set_variable('IP Address', ip_address)
                                    break

                                # if we cant find an ip just give up :(
                                if i == len(interfaces)-1: # Look to see if its the last interface and insert a newline
                                    self.set_variable('IP Address', 'can\'t find ip address :/')

                        # Done
                            break
                    except Exception as e:
                        print e

            # Parse _info.xml
                if self._info != None:
                    info_tree = ET.parse(self._info)
                    # Pull Location
                    self.set_variable('Location', info_tree.find("./location").text)

                    # Pull Computer Type
                    self.set_variable('Computer Type', info_tree.find("./computerType").text)

                    # Pull Encryption Software
                    self.set_variable('Encrtption Software', str(info_tree.find("./encryptionName").text))

                    # Pull HDD Encrypted?
                    self.set_variable('Hard Drive Encryption', 'Yes' if info_tree.find("./hddEncryption").text.upper() == 'TRUE' else 'No')

                    # Pull USB Encrypted?
                    self.set_variable('USB Encryption', 'Yes' if info_tree.find("./usbEncryption").text.upper() == 'TRUE' else 'No')

                    # Pull AV Name
                    self.set_variable('Antivirus Software', info_tree.find("./antivirusName").text)

                    # Pull AV Date
                    self.set_variable('Antivirus Definition Date', info_tree.find("./antivirusDate").text)

                    # Pull Notes
                    if info_tree.find("./notes").text:
                        self.set_variable('Notes', info_tree.find("./notes").text.replace(',', '').replace('\n',' '))


if __name__ == "__main__":
    main(sys.argv)


TODO = '''
        [X] - output in correct order
        [X] - windows update
        [ ] - error handeling for bad xml files
        [ ] - transpose output
        [ ] - save to file
        [X] - add ip addresss to the output
        [ ] - escape xml file input for csv delimiters
        '''