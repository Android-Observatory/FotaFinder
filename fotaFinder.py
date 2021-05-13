#!/usr/bin/env python3
#-*- coding: utf-8 -*-

import os
import sys
import datetime
import json
import configparser
import hashlib
import pickle

try:
    from dicttoxml import dicttoxml
except:
    print("{ERROR} YOU MUST HAVE DICTTOXML INSTALLED")
    sys.exit(1)

config = configparser.ConfigParser()
config.read('config.ini')

if len(config.sections()) == 0:
    try:
        import androguard
    except:
        print("{ERROR} YOU MUST HAVE ANDROGUARD INSTALLED")
        sys.exit(1)

    from androguard.misc import AnalyzeAPK
    from androguard.misc import AnalyzeDex
    from androguard.core.bytecodes.dvm_types import Kind

    # HARDCODED PATH TO DEXTRIPADOR
    sys.path = ["dextripador"] + sys.path

    from Dextripador import Extractor

else:
    androguard_path = ""
    dextripador_path = ""
    try:
        androguard_path = str(config['PATHS']['ANDROGUARD_PATH'])
        dextripador_path = str(config['PATHS']['DEXTRIPADOR_PATH'])

        # Check if the pickle with the dictionary exists in disk, otherwise reads the csv and dumps it
        if not os.path.isfile(config['PATHS']['MD5-ODEX-PICKLE']) and os.path.isfile(
                config['PATHS']['MD5-ODEX-CSV-FILE']):
            data_dict = {}
            lines = [l.strip() for l in open(config['PATHS']['MD5-ODEX-CSV-FILE']).readlines()]
            for line in lines:
                md5, path = line.split('|')
                data_dict[md5] = path
            pickle.dump(data_dict, open(config['PATHS']['MD5-ODEX-PICKLE'], 'wb'))
        elif os.path.isfile(config['PATHS']['MD5-ODEX-PICKLE']):
            with open(config['PATHS']['MD5-ODEX-PICKLE'], 'rb') as ifile:
                data_dict = pickle.load(ifile)

    except KeyError as ke:
        print("{ERROR} %s" % str(ke))
        sys.exit(1)

    sys.path = [androguard_path] + sys.path
    sys.path = [dextripador_path] + sys.path

    from androguard.misc import AnalyzeAPK
    from androguard.misc import AnalyzeDex
    from androguard.core.bytecodes.dvm_types import Kind
    from Dextripador import Extractor



import tempfile
import argparse

DEBUG_FLAG      = False
WARNING_FLAG    = False
ERROR_FLAG      = False
ANALYST_FLAG    = False

JSON_OUTPUT     = False
XML_OUTPUT      = False
FILE_OUTPUT     = False
PRETTY_PRINT    = False

Output_file_name = ""


class NoInputFileSuppliedException(Exception):
    pass

class Debug:
    def __init__(self):
        ''' Constructor of Debug class '''

    @staticmethod
    def log(msg):
        ''' print debug messages '''
        if DEBUG_FLAG:
            print("{DEBUG} %s - %s" % (datetime.datetime.now(), msg))

    @staticmethod
    def warning(msg, error):
        ''' print warning messages '''
        if WARNING_FLAG:
            print("{WARNING} %s - %s: %s" % (datetime.datetime.now(), msg, str(error)))
    
    @staticmethod
    def error(msg, error, exception):
        ''' print error messages '''
        if ERROR_FLAG:
            print("{ERROR} %s - %s: %s" % (datetime.datetime.now(), msg, str(error)))
        raise exception

    @staticmethod
    def analyst(msg):
        ''' messages good for the analyst '''
        if ANALYST_FLAG:
            print("{ANALYST} %s - %s" % (datetime.datetime.now(), msg))

class FotaAnalyzer:
    def __init__(self, path, is_dir, md5, dex):

        self.path = path
        self.is_dir = is_dir
        if not self.is_dir:
            self._md5 = md5
            self.dex = dex
        
        self.extractor = None
        self.is_multi_dex = False
        self.extracted_odex = False

    def __read_md5_odex_file(self):
        return pickle.load(open(config['PATHS']['MD5-ODEX-PICKLE'],'rb'))
    
    def __calculate_md5(self, fname):
        hash_md5 = hashlib.md5()
        with open(fname, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    
    def analyze(self):
        """
        User function of fotaFinder to apply the analysis, 
        it's necessary in case the input is a directory 
        with apks search for the files, and apply the analysis
        to each file.

        :returns: all the information from the analysis.
        :rtype: list
        """
        info = []

        if not self.is_dir:
            aux = self.extract_information(self.path)
            info.append(aux)
        else:
            for element in os.listdir(self.path):
                file_ = os.path.join(self.path, element)
                if os.path.isfile(file_) and file_.endswith(".apk"):
                    aux = self.extract_information(file_)
                    info.append(aux)

        return info

    def __androguard_analyze_apk(self, path_to_file):
        """
        Wrapper of androguard AnalyzeAPK, it will also use the library
        extractor from dextripador if there's no class, we will try to
        get the odex from same path, if it doesn't exist... No dex analysis

        :param path_to_file: file to analyze
        :returns: An APK object, array of DalvikVMFormat, and Analysis object.
        :rtype: return the :class:`~androguard.core.bytecodes.apk.APK`, list of :class:`~androguard.core.bytecodes.dvm.DalvikVMFormat`, and :class:`~androguard.core.analysis.analysis.Analysis` objects
        """
        Debug.log("Analyzing file \"%s\"" % (path_to_file))

        apk, classes_dex, analysis = AnalyzeAPK(path_to_file)

        if self.dex and len(self.dex) > 0:
            Debug.log("User gave dex %s to analyze instead" % self.dex)
            _, classes_dex, analysis = AnalyzeDex(self.dex)
            return apk, classes_dex, analysis

        if len(classes_dex) == 0:
            Debug.warning("class.dex file not present. Looking for odex to extract it", FileNotFoundError("File classes.dex not found in %s" % path_to_file))
            
            path_to_odex = path_to_file.replace('.apk', '.odex')
            odex_file_name = path_to_odex.split('/')[-1]

            if not os.path.isfile(path_to_odex):
                path_to_odex = '/'.join(path_to_file.split('/')[:-1]) + '/arm/' + odex_file_name
            if not os.path.isfile(path_to_odex):
                path_to_odex = '/'.join(path_to_file.split('/')[:-1]) + '/arm64/' + odex_file_name
            if not os.path.isfile(path_to_odex):
                path_to_odex = '/'.join(path_to_file.split('/')[:-1]) + '/oat/arm/' + odex_file_name
            if not os.path.isfile(path_to_odex):
                path_to_odex = '/'.join(path_to_file.split('/')[:-1]) + '/oat/arm64/' + odex_file_name

            if not os.path.isfile(path_to_odex):
                Debug.warning("odex file not found in the apk directory, computing md5 and looking in the list", FileNotFoundError("odex file not found in directory"))
                # Lookup the list of MD5-ODEX

                # If no md5 is provided by command line, calculate it
                if self._md5=='':
                    self._md5= self.__calculate_md5(path_to_file)

                self.odex_md5_dict = self.__read_md5_odex_file()

                if (self._md5 in self.odex_md5_dict):
                    path_to_odex=self.odex_md5_dict[self._md5]
                    Debug.log ("Found odex for md5=%s in the list. Path:%s"%(self._md5,path_to_odex))
                else:
                    Debug.warning("odex file for hash %s not present in the list. Looking in the apk directory"%self._md5, FileNotFoundError("odex file for %s not found in list" % self._md5))
                    raise FileNotFoundError("odex file not found neither in directory nor by md5")

            self.extractor = Extractor(path_to_odex)
            self.extractor.load()
            
            classes_dex, analysis = self.__call_extract_dex(0)

            if len(self.extractor.get_dex_files()) > 1:
                Debug.log("Apk %s has multiple dex" % (path_to_file))
                self.is_multi_dex = True
            
            self.extracted_odex = True


        return apk, classes_dex, analysis
    
    def __call_extract_dex(self, index):
        """ Method to extract dex file from extractor """
        fo = tempfile.NamedTemporaryFile()
        fo.close() # we're just interested in the name
        if len(self.extractor.get_dex_files()) > 0 and index < len(self.extractor.get_dex_files()):
            Debug.log("Extracting dex[%d] from odex to %s" % (index, fo.name + '.dex'))
            if self.extractor.extract_dex(index, fo.name + ".dex", True):
                # now try to analyze with androguard
                _, classes_dex, analysis = AnalyzeDex(fo.name + '.dex')
                return classes_dex, analysis
        return None, None

    def __check_dict_key(self, dictionary, key):
        """ Method to check a dictionary of boolean values """
        if (not key in dictionary) or (dictionary[key] == False):
            return True
        return False

    def extract_information(self, path_to_file):
        """
        Main analysis function, all the checks are
        done inside of this function, androguard is
        also called from here, and finally an information
        dictionary is returned with all the signals.

        :param path_to_file: the path given from user to the file, used to initialize androguard classes.
        :returns: all the signals values in information.
        :rtype: dict
        """
        # Function calls
        recovery_verifyPackage     = False
        recovery_installPackage    = False
        updateEngine_applyPayload  = False
        packageManager_installPackage = False
        packageManager_deletePackage  = False
        packageManager_grantRuntimePermission   = False
        packageManager_revokeRuntimePermission  = False
        ssl_tls                    = False
        http                       = False
        dynamic_dex_loading        = False
        
        # strings in code
        pm_install                 = False
        intent_vnd_android         = False
        cache_recovery_command     = False
        __update_package           = False
        ota_certs_zip              = False        
        ota_update_zip             = False

        # strings in names
        ota_in_package             = False
        ota_in_name                = False
        ota_in_filename            = False
        
        update_in_package          = False
        update_in_name             = False
        update_in_filename         = False

        upgrade_in_package         = False
        upgrade_in_name            = False
        upgrade_in_filename        = False

        install_in_package         = False
        install_in_name            = False
        install_in_filename        = False

        # list of permissions could exist
        install_package_perm       = False
        delete_packages_perm       = False
        
        # output information
        information                = {}

        index = 1

        try:
            apk, classes_dex, analysis = self.__androguard_analyze_apk(path_to_file)
        except Exception as e:
            Debug.warning("Error analyzing apk with androguard", e)
            return {
                "ERROR_TAG" : "EXCEPTION",
                "FILE" : path_to_file,
                "ERROR_MESSAGE" : str(e),
                "EXCEPTION_TYPE" : str(type(e))
            }

        application_name    = apk.get_app_name()
        file_name           = apk.get_filename()
        package_name        = apk.get_package()
        target_sdk_version  = apk.get_target_sdk_version()
        max_sdk_version     = apk.get_max_sdk_version()
        min_sdk_version     = apk.get_min_sdk_version()
        permissions         = apk.get_permissions()
        aosp_permissions    = apk.get_requested_aosp_permissions()
        tp_permissions      = apk.get_requested_third_party_permissions()
        shared_uid          = apk.get_attribute_value(tag_name='manifest',attribute='sharedUserId')
        
        # avoid complete paths
        file_name           = os.path.basename(file_name)

        # Show manifest information
        Debug.log("Extracted application name \"%s\"" % application_name)
        Debug.log("File name: \"%s\"" % file_name)
        Debug.log("Package name from manifest: \"%s\"" % package_name)
        Debug.log("Target SDK version: \"%s\"" % target_sdk_version)
        Debug.log("Max SDK version: \"%s\"" % max_sdk_version)
        Debug.log("Min SDK version: \"%s\"" % min_sdk_version)

        information['Application_Name'] = application_name
        information['File_Name']        = file_name
        information['Package_Name']     = package_name
        information['Target_Sdk']       = target_sdk_version
        information['Max_Sdk']          = max_sdk_version
        information['Min_Sdk']          = min_sdk_version
        information['System_App']       = False
        information['Extracted_Odex']   = self.extracted_odex

        if shared_uid == 'android.uid.system':
            information['System_App'] = True
        
        if "ota" in application_name.lower():
            ota_in_name = True
            Debug.log("App name includes \"ota\"")
        
        information['Ota_In_Name']          = ota_in_name

        if "ota" in package_name.lower():
            ota_in_package = True
            Debug.log("Package name includes \"ota\"")
        
        information['Ota_In_Package']       = ota_in_package

        if "ota" in file_name.lower():
            ota_in_filename = True
            Debug.log("File name includes \"ota\"")

        information['Ota_In_FileName']      = ota_in_filename

        if "update" in application_name.lower():
            update_in_name = True
            Debug.log("Application name includes \"update\"")
        
        information['Update_In_Name']       = update_in_name

        if "update" in package_name.lower():
            update_in_package = True
            Debug.log("Package name includes \"update\"")

        information['Update_In_Package']    = update_in_package

        if "update" in file_name.lower():
            update_in_filename = True
            Debug.log("File name includes \"update\"")

        information['Update_In_Filename']   = update_in_filename
        
        if "upgrade" in application_name.lower():
            upgrade_in_name = True
            Debug.log("Application name includes \"upgrade\"")
        information['Upgrade_In_Name']      = upgrade_in_name

        if "upgrade" in package_name.lower():
            upgrade_in_package = True
            Debug.log("Package name includes \"upgrade\"")
        information['Upgrade_In_Package']   = upgrade_in_package

        if "upgrade" in file_name.lower():
            upgrade_in_filename = True
            Debug.log("File name includes \"upgrade\"")
        information['Upgrade_In_Filename']  = upgrade_in_filename

        if "install" in application_name.lower():
            install_in_name = True
            Debug.log("Application name includes \"install\"")
        information['Install_In_Name'] = install_in_name

        if "install" in package_name.lower():
            install_in_package = True
            Debug.log("Package name includes \"install\"")
        information['Install_In_Package'] = install_in_package

        if "install" in file_name.lower():
            install_in_filename = True
            Debug.log("File name includes \"install\"")
        information['Install_In_Filename'] = install_in_filename

        # check of permission
        if "android.permission.INSTALL_PACKAGES" in aosp_permissions:
            install_package_perm            = True
        
        information['Instal_Packages_Permission'] = install_package_perm
        
        if "android.permission.DELETE_PACKAGES" in aosp_permissions:
            delete_packages_perm            = True

        information['Delete_Packages_Permission'] = delete_packages_perm

        """
        From here it starts all the analysis that depends on analysis
        object, we will create an infinite loop in order to analyze 
        all the dex files
        """
        while True:

            # check of functions
            if self.__check_dict_key(information, 'Recovery_VerifyPackage'):
                recovery_verifyPackage = self.checkVerifyPackage(analysis, package_name)
                if recovery_verifyPackage:
                    Debug.log("APK calls RecoverySystem.verifyPackage")
                
                information['Recovery_VerifyPackage']        = recovery_verifyPackage

            if self.__check_dict_key(information, 'Recovery_InstallPackage'):
                recovery_installPackage = self.checkInstallPackage(analysis, package_name)
                if recovery_installPackage:
                    Debug.log("APK calls RecoverySystem.installPackage")

                information['Recovery_InstallPackage']       = recovery_installPackage
            
            if self.__check_dict_key(information, 'UpdateEngine_ApplyPayload'):
                updateEngine_applyPayload = self.checkApplyPayload(analysis, package_name)
                if updateEngine_applyPayload:
                    Debug.log("APK calls UpdateEngine.applyPayload")

                information['UpdateEngine_ApplyPayload']         = updateEngine_applyPayload
            
            if self.__check_dict_key(information, 'PackageManager_installPackage'):
                packageManager_installPackage = self.checkPmInstallPackage(analysis, package_name)
                if packageManager_installPackage:
                    Debug.log("APK calls PackageManager.installPackage")

                information['PackageManager_installPackage'] = packageManager_installPackage

            if self.__check_dict_key(information, 'PackageManager_deletePackage'):
                packageManager_deletePackage = self.checkPmDeletePackage(analysis, package_name)
                if packageManager_deletePackage:
                    Debug.log("APK calls PackageManager.deletePackage")

                information['PackageManager_deletePackage'] = packageManager_deletePackage

            if self.__check_dict_key(information, 'PackageManager_grantRuntimePermission'):
                packageManager_grantRuntimePermission = self.checkPmGrantRuntimePermission(analysis, package_name)
                if packageManager_grantRuntimePermission:
                    Debug.log("APK calls PackageManager.grantRuntimePermission")

                information['PackageManager_grantRuntimePermission'] = packageManager_grantRuntimePermission

            if self.__check_dict_key(information, 'PackageManager_revokeRuntimePermission'):
                packageManager_revokeRuntimePermission = self.checkPmRevokeRuntimePermission(analysis, package_name)
                if packageManager_revokeRuntimePermission:
                    Debug.log("APK calls PackageManager.revokeRuntimePermission")

                information['PackageManager_revokeRuntimePermission'] = packageManager_revokeRuntimePermission
            
            if self.__check_dict_key(information, 'SSL/TLS'):
                ssl_tls = self.checkSSLTLS(analysis, package_name)
                if ssl_tls:
                    Debug.log("APK uses SSL/TLS")
                information['SSL/TLS'] = ssl_tls
            
            if self.__check_dict_key(information, 'HTTP'):
                http = self.checkHTTP(analysis, package_name)
                if http:
                    Debug.log("APK uses HTTP")
                information['HTTP'] = http

            if self.__check_dict_key(information, 'Hash_Algorithms'):
                hash_algorithms = self.checkHashAlgorithms(analysis, package_name)
                if len(hash_algorithms) > 0:
                    Debug.log("APK Uses next algorithms: %s" % (','.join(hash_algorithms)))
                information['Hash_Algorithms'] = hash_algorithms
            
            if self.__check_dict_key(information, 'Dynamic_Dex_Loading'):
                dex_loaders = self.checkDexClassLoading(analysis, package_name)
                if len(dex_loaders) > 0:
                    Debug.log("APK uses dynamic dex loading in: %s" % (','.join(dex_loaders)))
                    dynamic_dex_loading = True
                information['Dynamic_Dex_Loading'] = dynamic_dex_loading
                information['Dynamic_Dex_Loading_Refs'] = dex_loaders

            # check of string

            if self.__check_dict_key(information, 'Pm_Install'):
                pm_install = self.checkPmInstall(analysis, package_name)
                if pm_install:
                    Debug.log("APK uses pm install")
                
                information['Pm_Install']           = pm_install

            if self.__check_dict_key(information, 'Intent_Vnd_Android'):
                intent_vnd_android = self.checkVndAndroidPackageArchive(analysis, package_name)
                if intent_vnd_android:
                    Debug.log("APK uses application/vnd.android.package-archive")

                information['Intent_Vnd_Android']   = intent_vnd_android

            if self.__check_dict_key(information, 'Cache_Recovery_Command_Update'):
                cache_recovery_command = self.checkCacheRecoveryCommand(analysis, package_name) or \
                    self.checkCacheRecoveryAndCommand(analysis, package_name)

                if cache_recovery_command:
                    Debug.log("APK probably modifies file /cache/recovery/command")                    
                    
                __update_package = self.check__Update_Package(analysis, package_name)
                if __update_package:
                    Debug.log("APK has string --update_package")
                
                if cache_recovery_command and __update_package:
                    information['Cache_Recovery_Command_Update'] = True
                else:
                    information['Cache_Recovery_Command_Update'] = False

            if self.__check_dict_key(information, 'ota_certs_zip'):
                ota_certs_zip = self.checkOTACertsZip(analysis, package_name)
                if ota_certs_zip:
                    Debug.log("APK refers to otacerts.zip")

                information['ota_certs_zip']   = ota_certs_zip

            if self.__check_dict_key(information, 'ota_update_zip'):
                ota_update_zip = self.checkOTAUpdateZip(analysis, package_name)
                if ota_update_zip:
                    Debug.log("APK refers to otacerts.zip")

                information['ota_update_zip']   = ota_update_zip
            
            # commonly apks and odex will contain
            # just one dex file
            if not self.is_multi_dex:
                break
            
            # in case more than one dex is found
            # or more than one dex was extracted
            # from odex.
            if index >= len(self.extractor.get_dex_files()):
                break
            
            classes_dex, analysis = self.__call_extract_dex(index)
            index += 1
            
        return information

    def checkReferencesToMethodPackageBackTrack(self, analysis, package_name, class_name, method_name):
        """
        Method to search calls to a given method from a class
        in a given package, as it's possible that the method
        it's not exactly in the given package, we do a backtrack
        analysis in package name path, searching if the method
        is in a related package.

        :param analysis: analysis object from Androguard, used to retrieve information.
        :param package_name: package name where to search the class-method.
        :param class_name: class name that includes the method.
        :param method_name: method we look for.
        :returns: if method is cross referenced in given package or related.
        :rtype: bool
        """
        classes = list(analysis.get_classes())
        methods = []
        
        Debug.log("Checking for the presence of class %s and method %s" % (class_name, method_name))
            
        # package paths in calls are given with
        # slashes
        package_name = package_name.replace(".","/")

        for class_ in classes:
            if class_name == str(class_.name): # search for specific class
                Debug.log("Class %s found in apk classes" % class_name)
                methods = list(class_.get_methods())
                break

        for method_ in methods:
            if method_name == str(method_.name): # search for specific method
                Debug.log("Method %s found in the class" % method_name)
                xrefs_to_method = method_.get_xref_from()
                # check in all the xrefs in any of them
                # is from the specified package name

                # now we will implement a search on previous
                # nodes of the package, the probability that
                # the call is correct, must be taken in consideration
                n_of_backs = package_name.count('/')
                splitted_package = package_name.split('/')

                for i in range(n_of_backs, -1, -1):
                    new_package_name = '/'.join(splitted_package[:i+1])
                    for _, call, _ in xrefs_to_method:
                        if new_package_name in str(call.class_name):
                            Debug.analyst("{} -- {} is called from -> {} -- {}".format(class_name, method_name, call.class_name, call.name))
                            Debug.log("Found call!")
                            Debug.log("[checkReferencesToMethodPackageBackTrack] - call found in %d index of %d, probability %f" % (i, n_of_backs, i/n_of_backs))
                            Debug.log("[checkReferencesToMethodPackageBackTrack] - in package %s of package %s" % (new_package_name, package_name))
                            if i/n_of_backs >= 0.25:
                                return True
                            # Removed this, with this false
                            # we're only checking one with 
                            # new_package_name in class_name
                            #else:
                            #    return False

        return False
    
    def checkReferencesToMethod(self, analysis, package_name, class_name, method_name):
        """
        Method to search calls to a given method from a class
        in a given package. Here we only look for exact
        matches of package name.

        :param analysis: analysis object from Androguard, used to retrieve information.
        :param package_name: package name where to search the class-method.
        :param class_name: class name that includes the method.
        :param method_name: method we look for.
        :returns: if method is cross referenced in given package.
        :rtype: bool
        """
        classes = list(analysis.get_classes())
        methods = []
        
        Debug.log("Checking for the presence of class %s and method %s" % (class_name, method_name))
            
        # package paths in calls are given with
        # slashes
        package_name = package_name.replace(".","/")

        for class_ in classes:
            if class_name == str(class_.name): # search for specific class
                Debug.log("Class %s found in apk classes" % class_name)
                methods = list(class_.get_methods())
                break

        for method_ in methods:
            if method_name == str(method_.name): # search for specific method
                Debug.log("Method %s found in the class" % method_name)
                xrefs_to_method = method_.get_xref_from()
                # check in all the xrefs in any of them
                # is from the specified package name
                for _, call, _ in xrefs_to_method:
                    Debug.analyst("{} -- {} is called from -> {} -- {}".format(class_name, method_name, call.class_name, call.name))
                    if package_name in str(call.class_name):
                        Debug.log("Found call!")
                        return True

        return False
    
    def checkReferencesToMethodGetMethodXrefs(self, analysis, package_name, class_name, method_name):
        """
        Get the cross-references for a method of a given class,
        that match with the given package name.

        :param analysis: analysis object from Androguard, used to retrieve information.
        :param package_name: package name where to search the class-method.
        :param class_name: class name that includes the method.
        :param method_name: method we look for.
        :returns: the cross-references to the method.
        :rtype: list
        """
        classes = list(analysis.get_classes())
        methods = []
        xrefs = []
        
        Debug.log("Checking for the presence of class %s and method %s" % (class_name, method_name))
            
        # package paths in calls are given with
        # slashes
        package_name = package_name.replace(".","/")

        for class_ in classes:
            if class_name == str(class_.name): # search for specific class
                Debug.log("Class %s found in apk classes" % class_name)
                methods = list(class_.get_methods())
                break

        for method_ in methods:
            if method_name == str(method_.name): # search for specific method
                Debug.log("Method %s found in the class" % method_name)
                xrefs_to_method = method_.get_xref_from()
                # check in all the xrefs in any of them
                # is from the specified package name
                for _, call, _ in xrefs_to_method:
                    if package_name in str(call.class_name):
                        Debug.analyst("{} -- {} is called from -> {} -- {}".format(class_name, method_name, call.class_name, call.name))
                        Debug.log("Found call!")
                        xrefs.append(call)

        return xrefs

    def __is_call_inst(self, instruction):
        """ Quickly check if given instruction is some kind of call instruction """
        # https://github.com/androguard/androguard/blob/master/androguard/core/bytecodes/dvm.py#L6063
        # https://github.com/androguard/androguard/blob/master/androguard/core/bytecodes/dvm.py#L6210
        invoke_kind = [Kind.METH, Kind.METH_PROTO, Kind.CALL_SITE]
        try:
            if instruction.get_kind() in invoke_kind:
                return True
            else:
                return False
        except:
            # no Kind on instruction
            # return false
            return False
    
    def __is_const_string(self, instruction):
        """ Quickly check if given instruction is a const-string instruction """
        # https://github.com/androguard/androguard/blob/master/androguard/core/bytecodes/dvm.py#L6081
        # https://github.com/androguard/androguard/blob/master/androguard/core/bytecodes/dvm.py#L6082
        try:
            if instruction.get_kind() == Kind.STRING:
                return True
            else:
                return False
        except:
            return False

    '''
    Function checks in code.
    '''
    def checkVerifyPackage(self, analysis, package_name):
        return self.checkReferencesToMethod(analysis=analysis, package_name=package_name, class_name="Landroid/os/RecoverySystem;",method_name="verifyPackage")

    def checkInstallPackage(self, analysis, package_name):
        return self.checkReferencesToMethod(analysis=analysis, package_name=package_name, class_name="Landroid/os/RecoverySystem;",method_name="installPackage")

    def checkApplyPayload(self, analysis, package_name):
        return self.checkReferencesToMethod(analysis=analysis, package_name=package_name, class_name="Landroid/os/UpdateEngine;",method_name="applyPayload")
    
    def checkPmInstallPackage(self, analysis, package_name):
        return self.checkReferencesToMethod(analysis=analysis, package_name=package_name, class_name="Landroid/content/pm/PackageManager;",method_name="installPackage")
    
    def checkPmDeletePackage(self, analysis, package_name):
        return self.checkReferencesToMethod(analysis=analysis, package_name=package_name, class_name="Landroid/content/pm/PackageManager;",method_name="deletePackage")

    def checkPmGrantRuntimePermission(self, analysis, package_name):
        return self.checkReferencesToMethod(analysis=analysis, package_name=package_name, class_name="Landroid/content/pm/PackageManager;",method_name="grantRuntimePermission")

    def checkPmRevokeRuntimePermission(self, analysis, package_name):
        return self.checkReferencesToMethod(analysis=analysis, package_name=package_name, class_name="Landroid/content/pm/PackageManager;",method_name="revokeRuntimePermission")
    
    def checkSSLTLS(self, analysis, package_name):
        use_of_ssl = False
        use_of_http_object = False
        
        # detect javax.net.ssl.TrustManagerFactory
        use_of_ssl |= self.checkReferencesToMethodPackageBackTrack(analysis=analysis, package_name=package_name, class_name="Ljavax/net/ssl/TrustManagerFactory;",method_name="getInstance")
        # detect org.apache.http.conn.ssl.SSLSocketFactory
        use_of_ssl |= self.checkReferencesToMethodPackageBackTrack(analysis=analysis, package_name=package_name, class_name="Lorg/apache/http/ssl/SSLSocketFactory;",method_name="getSocketFactory")
        # detect javax.net.ssl.SSLContext
        use_of_ssl |= self.checkReferencesToMethodPackageBackTrack(analysis=analysis, package_name=package_name, class_name="Ljavax/net/ssl/SSLContext;",method_name="getInstance")
        # detect the use of HttpsURLConnection setSSLSocketFactory
        use_of_ssl |= self.checkReferencesToMethodPackageBackTrack(analysis=analysis, package_name=package_name, class_name="Ljava/net/HttpURLConnection;",method_name="setSSLSocketFactory")
        # detect javax.net.ssl.HttpsURLConnection 
        use_of_ssl |= self.checkReferencesToMethodPackageBackTrack(analysis=analysis, package_name=package_name, class_name="Ljavax/net/ssl/HttpsURLConnection;",method_name="<init>")

        # detect org.apache.http.impl.client.DefaultHttpClient
        use_of_http_object |= self.checkReferencesToMethodPackageBackTrack(analysis=analysis, package_name=package_name, class_name="Lorg/apache/http/impl/client/DefaultHttpClient;",method_name="<init>")
        # detect java.net.URL openConnection
        use_of_http_object |= self.checkReferencesToMethodPackageBackTrack(analysis=analysis, package_name=package_name, class_name="Ljava/net/URL;",method_name="openConnection")
        # detect java.net.HttpURLConnection 
        use_of_http_object |= self.checkReferencesToMethodPackageBackTrack(analysis=analysis, package_name=package_name, class_name="Ljava/net/HttpURLConnection;",method_name="<init>")
        # detect javax.net.ssl.HttpsURLConnection
        use_of_http_object |= self.checkReferencesToMethodPackageBackTrack(analysis=analysis, package_name=package_name, class_name="Ljavax/net/ssl/HttpsURLConnection;",method_name="<init>")

        return (use_of_ssl & use_of_http_object)
    
    def checkHTTP(self, analysis, package_name):
        use_of_http_object = False

        # detect org.apache.http.impl.client.DefaultHttpClient
        use_of_http_object |= self.checkReferencesToMethodPackageBackTrack(analysis=analysis, package_name=package_name, class_name="Lorg/apache/http/impl/client/DefaultHttpClient;",method_name="<init>")
        # detect java.net.URL openConnection
        use_of_http_object |= self.checkReferencesToMethodPackageBackTrack(analysis=analysis, package_name=package_name, class_name="Ljava/net/URL;",method_name="openConnection")
        # detect java.net.HttpURLConnection 
        use_of_http_object |= self.checkReferencesToMethodPackageBackTrack(analysis=analysis, package_name=package_name, class_name="Ljava/net/HttpURLConnection;",method_name="<init>")
        
        return use_of_http_object
    
    def checkHashAlgorithms(self, analysis, package_name):
        """
        Method to detect the use of the API MessageDigest,
        it could be useful as sometimes this API is used to
        verify an update package instead of the verifyPackage
        method.

        :param analysis: analysis object from Androguard.
        :param package_name: package where to search the use of MessageDigest.
        :returns: if found, the list of detected algorithms used in MessageDigest.
        :rtype: list
        """
        detected_algorithms = set()
        # detect by MessageDigest
        messageDigest_xrefs = self.checkReferencesToMethodGetMethodXrefs(analysis=analysis, package_name=package_name, class_name="Ljava/security/MessageDigest;", method_name="getInstance")

        for method in messageDigest_xrefs:
            for block in method.get_basic_blocks():
                instructions = list(block.get_instructions())
                for i in range(len(instructions)):
                    if self.__is_call_inst(instructions[i]) and 'Ljava/security/MessageDigest;->getInstance' in str(instructions[i]):
                        used_register = instructions[i].get_operands()[0][1]
                        Debug.log("[checkHashAlgorithms] - found MessageDigest->getInstance, string register %d" % (used_register))
                        found_string = False
                        for j in range(i, -1, -1):
                            if self.__is_const_string(instructions[j]) and used_register == instructions[j].get_operands()[0][1]:
                                algorithm = instructions[j].get_operands()[1][2]
                                Debug.log("[checkHashAlgorithms] - found const-string from MessageDigest->getInstance, algorithm %s" % (algorithm))
                                detected_algorithms.add(algorithm)
                                found_string = True
                                break
                        if found_string:
                            break
                            
        
        return list(detected_algorithms)
    
    def checkDexClassLoading(self, analysis, package_name):
        """
        Detect the dynamic loading of dex files all the DEX file.

        :param analysis: analysis object from Androguard.
        :param package_name: not used, probably removed in later releases.
        :return: list of references where Dex are dynamically loaded.
        :rtype: list
        """
        detected_calls = set()
        # detect dalvik.system.DexClassLoader
        loadClass_xrefs = self.checkReferencesToMethodGetMethodXrefs(analysis=analysis, package_name='', class_name="Ldalvik/system/DexClassLoader;", method_name="loadClass")
        for method in loadClass_xrefs:
            detected_calls.add(str(method.class_name) + "->" + str(method.name))
        
        return list(detected_calls)

    '''
    String checks in code
    '''
    def checkCacheRecoveryCommand(self, analysis, package_name):
        return self.checkReferencesToString(analysis=analysis, package_name=package_name, regex_string="/cache/recovery/command")
    
    def checkCacheRecoveryAndCommand(self, analysis, package_name):
        if not self.checkReferencesToString(analysis=analysis, package_name=package_name, regex_string="/cache/recovery"):
            return False
        if not self.checkReferencesToString(analysis=analysis, package_name=package_name, regex_string="command"):
            return False
        
        cache_recovery_classes = self.getClassesFromReferencesToString(analysis=analysis, package_name=package_name, regex_string="/cache/recovery")
        if len(cache_recovery_classes) == 0:
            return False
        
        command_classes = self.getClassesFromReferencesToString(analysis=analysis, package_name=package_name, regex_string="command")
        if len(command_classes) == 0:
            return False
        
        for class_ in cache_recovery_classes:
            if class_ in command_classes:
                Debug.analyst("'/cache/recovery' and 'command' are used both in the --> {} as separated strings".format(class_))
                return True
        return False

    def check__Update_Package(self, analysis, package_name):
        return self.checkReferencesToString(analysis=analysis, package_name=package_name, regex_string="--update_package")

    def checkPmInstall(self, analysis, package_name):
        return self.checkReferencesToString(analysis=analysis, package_name=package_name, regex_string="pm install.*")

    def checkVndAndroidPackageArchive(self, analysis, package_name):
        return self.checkReferencesToString(analysis=analysis, package_name=package_name, regex_string="application/vnd.android.package-archive")

    def checkOTACertsZip(self, analysis, package_name):
        return self.checkReferencesToString(analysis=analysis, package_name=package_name, regex_string=".*otacerts.zip")

    def checkOTAUpdateZip(self, analysis, package_name):
        return self.checkReferencesToString(analysis=analysis, package_name=package_name, regex_string=".*ota_update.zip")
    
    def checkReferencesToString(self, analysis, package_name, regex_string):
        """
        Method to search for a given regex in a given package.

        :param analysis: analysis object from Androguard.
        :param package_name: package name where regex must be.
        :param regex_string: regex to look for.
        :return: boolean saying if the regex has been found or not.
        :rtype: bool
        """
        string_analysis = list(analysis.find_strings(regex_string))

        # package paths in calls are given with
        # slashes
        package_name = package_name.replace(".","/")

        for string in string_analysis:
            xrefs_to_string = string.get_xref_from()
            for _, method in xrefs_to_string:
                Debug.analyst("{} is used in --> {} -- {}".format(regex_string, method.class_name, method.name))
                if package_name in str(method.class_name):
                    Debug.log("Found used string!")
                    return True
        
        return False

    '''
    Some getters
    '''
    def getClassesFromReferencesToString(self, analysis, package_name, regex_string):
        """
        Get all the classes where a regex string has been found.

        :param analysis: analysis object from Androguard.
        :param package_name: package name where to find the regex.
        :param regex_string: regex string to search.
        :returns: list of classes where the regex have been found.
        :rtype: list
        """
        string_analysis = list(analysis.find_strings(regex_string))
        classes = []

        # package paths in calls are given with
        # slashes
        package_name = package_name.replace(".","/")

        for string in string_analysis:
            xrefs_to_string = string.get_xref_from()
            for _, method in xrefs_to_string:
                if package_name in str(method.class_name) and str(method.class_name) not in classes:
                    classes.append(str(method.class_name))
        
        if len(classes):
            Debug.analyst("{} is used in all these classes --> {}".format(regex_string, classes))

        return classes

def writeOutput(info,prettyPrint=False):
    """ Simple method used to print or dump to a file the output, probably will be included inside of class """
    if JSON_OUTPUT:
        if prettyPrint:
            json_dump = json.dumps(info, indent=4, sort_keys=True)
        else:
            json_dump = json.dumps(info)

    if XML_OUTPUT:
        xml_dump = dicttoxml(info, custom_root='output', attr_type=False)

    if FILE_OUTPUT:
        if JSON_OUTPUT and XML_OUTPUT:
            with open('json_'+Output_file_name,'w') as file_:
                file_.write(json_dump)
            with open('xml_'+Output_file_name,'w') as file_:
                file_.write(xml_dump)
        elif JSON_OUTPUT:
            with open(Output_file_name,'w') as file_:
                file_.write(json_dump)
        elif XML_OUTPUT:
            with open('xml_'+Output_file_name,'w') as file_:
                file_.write(xml_dump)
    else:
        if JSON_OUTPUT and XML_OUTPUT:
            print(json_dump)
            print("\n\n")
            print(xml_dump)
        if JSON_OUTPUT:
            print(json_dump)
        elif XML_OUTPUT:
            print(xml_dump)


def main():
    global DEBUG_FLAG
    global WARNING_FLAG
    global ERROR_FLAG
    global ANALYST_FLAG
    global JSON_OUTPUT
    global XML_OUTPUT
    global FILE_OUTPUT
    global Output_file_name
    global PRETTY_PRINT
    
    fotaAnalyzer = None

    parser = argparse.ArgumentParser(description="FotaAnalyzer tool to check parts in apks to detect if it's a fota app")
    parser.add_argument("-d","--debug",action="store_true",help="Show debug messages")
    parser.add_argument("-w","--warning", action="store_true",help="Show warning messages")
    parser.add_argument("-e","--error", action="store_true",help="Show error messages")
    parser.add_argument("-a","--analyst", action="store_true",help="Show messages for the analyst")
    parser.add_argument("-i", "--input", type=str,help="APK or Directory to analyze", required=True)
    parser.add_argument("--dex", type=str, help="Dex to analyze with the APK (used for example if you extracted dex with dextra)")
    parser.add_argument("-p","--pretty", action="store_true",help="Output with pretty print")
    parser.add_argument("--json",action="store_true",help="Output as json (default)")
    parser.add_argument("--xml",action="store_true",help="Output as xml")
    parser.add_argument("-o","--output",type=str,help="Specify output file (stdout if not specified")
    parser.add_argument("-m","--md5hash",nargs='?',const='',type=str,help="Specify the md5 hash of the apk (if file is given)")
    args = parser.parse_args()

    if args.debug:
        DEBUG_FLAG = True

    if args.warning:
        WARNING_FLAG = True

    if args.error:
        ERROR_FLAG = True

    if args.analyst:
        ANALYST_FLAG = True
    
    if args.pretty:
        PRETTY_PRINT = True

    Debug.log("File/Path to analyze specified by user \"%s\"" % args.input);

    if args.json:
        JSON_OUTPUT = True
        Debug.log("JSON Output selected")

    if args.xml:
        XML_OUTPUT = True
        Debug.log("XML Output selected")

    if (not JSON_OUTPUT) and (not XML_OUTPUT):
        JSON_OUTPUT = True
        Debug.log("No output type selected, JSON by default")

    if args.output is not None:
        FILE_OUTPUT = True
        Debug.log("Output File to dump analysis \"%s\"" % args.output)
        Output_file_name = args.output
    
    md5=args.md5hash
    dex=args.dex
    
    if os.path.isdir(args.input):
        fotaAnalyzer = FotaAnalyzer(args.input, True, md5=md5, dex=dex)
    elif os.path.isfile(args.input):
        fotaAnalyzer = FotaAnalyzer(args.input, False, md5=md5, dex=dex)

    info = fotaAnalyzer.analyze()

    Debug.log("Info of application %s" % str(info))
    
    writeOutput(info,PRETTY_PRINT)

if __name__ == '__main__':
    main()
