import os, datetime, sys, re
import xml.etree.ElementTree as ET

def main(argv):

    # Welcome banner
    print '*===========================================================*'
    print '* WinAudit.py - v4.0                                        *'
    print '* Fork me on GitHub! - https://github.com/scott-be/winaudit *'
    print '* Happy Hacking!                                            *'
    print '*===========================================================*'

    # Get the file path if no file path is provided as a argument
    folderpath = raw_input('Enter a file path: ').strip().replace('"','') if len(argv) == 1 else argv[1]

    # Look for _winaudit.xml and _info.xml files and save into dictionary
    for root, dirs, files in os.walk(folderpath):
        xml_files = {'winaudit' : None, 'info' : None} # Used to save a two element dictionary containing the _winaudit and _info files
        
        for file in files: # Look for the two files and save them to the dictionary
            if file.endswith('.xml'):
                if file.endswith('_winaudit.xml'):
                    xml_files['winaudit'] = root + os.sep + file
                if file.endswith('_info.xml'):
                    xml_files['info'] = root + os.sep + file

                scan = WinAudit(xml_files['winaudit'], xml_files['info']) # create a new WinAudit object and pass it the _winaudit and _info files
                scan.audit() # parse the files
                scan.print_variables() # print the files

class WinAudit(object):
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
                'Notes'                     : ''
            }

        def set_variable(self, k, v):
            self.variables[k] = v;

        def get_variable(self, k):
            return self.variables.get(k, None)

        def print_variables(self):
            print self._winaudit
            print self._info
            for k, v in self.variables.iteritems():
                print k + '\t' + v

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
        [ ] - output in correct order
        [X] - windows update
        [ ] - error handeling for bad xml files
        [ ] - transpose output
        [ ] - save to file
        [ ] - add ip addresss to the output
        '''