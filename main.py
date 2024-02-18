from ast import Return
import subprocess
import os
import sys
import time
import hashlib
import socket
import cpuinfo

from PyQt5 import QtWidgets
from PyQt5.QtCore import QThread, pyqtSignal
from window import Ui_StackedWidget


class Operations(QThread):
    # ------------------------------------------------------SIGNALS------------------------------------------------
    percentageChange  = pyqtSignal('PyQt_PyObject')
    currentStatus     = pyqtSignal('PyQt_PyObject')
    process_error     = pyqtSignal(bool)
    currently_running = pyqtSignal(bool)

    # ---------------------------------------------------FILE_PATHS------------------------------------------------
    home_dir    = '/home/pi/Desktop/'
    working_dir = f'{home_dir}EFI_Unlock/'
    backup_dir  = f'{home_dir}EFI_Backups/'
    read_path   = working_dir + 'read.bin'
    write_path  = working_dir + 'write.bin'

    # ------------------------------------------------------COMMANDS-----------------------------------------------

    fr_probe    = 'flashrom -p linux_spi:dev=/dev/spidev1.2,spispeed=10000'
    cfr         = 'chrome_' + fr_probe
    read_cmd    = cfr + ' -r ' + read_path
    verify_cmd  = cfr + ' -v ' + read_path
    write_cmd   = cfr + ' -w ' + write_path
    # -----------------------------------------------------OPERATIONS----------------------------------------------

    def __init__(self, operation, serial=''):
        QThread.__init__(self)
        self.operation = operation
        self.new_serial = serial

    def run(self):
        self.deleteFiles()
        self.currently_running.emit(True)

        if not self.readStage():
            self.process_error.emit(True)
            self.currently_running.emit(False)
            return
        
        if not self.updateStage():
            self.process_error.emit(True)
            self.currently_running.emit(False)
            return
        
        if not self.writestage():
            self.process_error.emit(True)
            self.currently_running.emit(False)
        
        self.finishStage()
        self.currently_running.emit(False)

    def readStage(self):

        self.updateProgressBar(0)
        self.updateStatus(f"\n{self.operation} Selected. Starting {self.operation} operation.\n Reading device firmware...")

        for op in ["First", "Second"]:

            if not self.readDeviceFirmware():
                print("Unable to read firmware")
                return False

            with open(self.read_path, 'rb') as firmware_file:
                data = firmware_file.read()
                md5 = hashlib.md5(data).hexdigest()

                if op == "First":
                    first_read_md5 = md5
                    self.updateStatus(f"First read: {first_read_md5}")
                    self.updateProgressBar(10)

                if op == "Second":
                    second_read_md5 = md5
                    self.updateProgressBar(40)
        

        if first_read_md5 != second_read_md5:
            self.updateStatus(
                f"<span style='color:#ff0000;'>Bad Read. \nFirst read: {first_read_md5}"
                f"\Second read: {second_read_md5}<\\span>")
            return False

        else:
            self.updateStatus(
                f"Reads Verified. \nFirst read: {first_read_md5}\nThis read: {second_read_md5}")
            return True

    def readDeviceFirmware(self):

        with subprocess.Popen(self.read_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as process:
            try:
                result, errors = process.communicate(timeout=32)
                if errors == b'':
                    self.updateStatus("<span style='color:#196F3D;'>" + result.decode('utf-8') + "<\\span>")
                else:
                    self.updateStatus("<span style='color:#196F3D;'>" + result.decode('utf-8') + "<\\span>")
                    return False


            except subprocess.TimeoutExpired:
                process.terminate()
                self.updateStatus(
                    "\n<span style='color:#ff0000;'>Error reading device firmware."
                    " \nTimed out reading after 32 seconds. <\\span>")
                self.process_error.emit(True)
                return False


            except Exception as error:
                self.updateStatus(
                    "\n<span style='color:#ff0000;'>Error reading\n" + str(error) + "<\\span>")
                process.terminate()
                self.process_error.emit(True)
                return False

        return True

    def updateStage(self):
        self.updateStatus("Firmware loaded into memory.")
        self.updateProgressBar(60)

        if self.operation == "Deprovision": #Replaces two bytes in firmware to remove EFI locks

            self.skipwrite = False

            cb_var = '430042004600320043004300330032'
            cb_rpl = '000042004600320043004300330032'

            self.updateStatus("Beginning Deprovision...")
            with open(self.read_path, 'rb') as f:
                data = f.read().hex()
            cb_pres = cb_var in data
            if not cb_pres:
                self.updateStatus("CB Variable Not Found")
                self.process_error.emit(True)
                return False
            else:
                with open(self.read_path, 'rb') as f:
                    data = f.read().hex()
                data = data.replace(cb_var, cb_rpl)
                with open(self.write_path, 'wb') as f:
                    f.write(bytes.fromhex(data))
                self.updateStatus("CB Variable Removed")

        if self.operation == 'Serial': #Locates SSN pointer and replaces S/N with input from user, converts to uppercase automatically.

            self.skipwrite = False
            
            self.updateStatus("Beginning Serial Update...")
            with open(self.read_path, 'rb') as f:
                ssn_pointer = '73736e0c'
                data = f.read().hex()

                ssn_location = data.find(ssn_pointer)
                current_serial_hex = data[ssn_location + 10:ssn_location + 34]
                current_serial = bytes.fromhex(current_serial_hex)
                try:
                    current_serial = current_serial.decode('UTF-8')
                except UnicodeDecodeError as error:
                    self.updateStatus("Decode Error")
                    self.updateStatus(error)
                    return False
                self.updateStatus(f"Current Serial found.\n{current_serial}")

                self.updateStatus("Verifying size of new serial against old serial...")
                new_serial = self.new_serial.text()
                if len(new_serial) != len(current_serial):
                    self.updateStatus(f"Invalid Serial length.\n"
                                      f"Expected length:{len(current_serial)} got length:{len(new_serial)}")
                    self.process_error.emit(True)
                    return False
                else:
                    self.updateStatus("Serial length validated. Writing to file...")
                    new_serial_hex = new_serial.encode("UTF-8").upper()
                    new_serial_hex = new_serial_hex.hex()
                    data = data.replace(current_serial_hex, new_serial_hex)
                    with open(self.write_path, 'wb') as f:
                        f.write(bytes.fromhex(data))
                    self.updateStatus("Serial Updated.")

        if self.operation == 'Retrieve Serial':

            self.skipwrite = True
            with open(self.read_path, 'rb') as f:
                ssn_pointer = '73736e0c'
                data = f.read().hex()

                ssn_location = data.find(ssn_pointer)
                current_serial_hex = data[ssn_location + 10:ssn_location + 34]
                current_serial = bytes.fromhex(current_serial_hex)
                current_serial = current_serial.decode('UTF-8')
                self.updateStatus(f"Current Serial:{current_serial}")

        return True
    # TODO Return error for write verification fail in flashrom, in most cases it seems a non issue and         writes still work, but that may not always be the case.
    # TODO Make parameters for read firmware to use it for both reading and writing functions

    def writestage(self):
        if self.operation == "Retrieve Serial":
            return True
        else:
            self.updateStatus("Writing Updated Firmware...")
            self.updateProgressBar(70)
            with subprocess.Popen(self.write_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as process:
                try:
                    result, errors = process.communicate(timeout=45)
                    if errors == b'':
                        self.updateStatus("<span style='color:#196F3D;'>" + result.decode('utf-8') + "<\\span>")
                    else:
                        self.updateStatus("<span style='color:#196F3D;'>" + result.decode('utf-8') + "<\\span>")
                        return False
                except subprocess.TimeoutExpired:
                    process.terminate()
                    self.updateStatus(
                        "\n<span style='color:#ff0000;'>Error writing device firmware. \nTimed out reading after 32 seconds. <\\span>")
                    self.process_error.emit(True)
                    return False
                except Exception as error:
                    self.updateStatus(
                        "\n<span style='color:#ff0000;'>Error writing\n" + str(error) + "<\\span>")
                    process.terminate()
                    self.process_error.emit(True)
                    return False
            self.updateStatus("Completed Write")
            return True

    def updateStatus(self, message):
        self.currentStatus.emit(message)

    def updateProgressBar(self, percent_val):
        self.percentageChange.emit(percent_val)

    def deleteFiles(self):
        self.updateStatus("Removing old files...")
        if os.path.exists(self.read_path):
            os.remove(self.read_path)
        if os.path.exists(self.write_path):
            os.remove(self.write_path)

    def finishStage(self):
        self.percentageChange.emit(100)
        self.currentStatus.emit(
            f"{self.operation} Operation Verified.")
        self.currentStatus.emit("Finished.")
        time.sleep(3)
        self.percentageChange.emit(0)
        self.currently_running.emit(False)


class Probe(QThread):
    signal = pyqtSignal('PyQt_PyObject')

    def __init__(self):
        QThread.__init__(self)
        self.flashrom = "flashrom -p linux_spi:dev=/dev/spidev1.2,spispeed=10000"

    def run(self):
        while True:
            cmd_result = subprocess.call(self.flashrom, stdout=subprocess.DEVNULL, shell=True)
            cmd_capture = subprocess.run(self.flashrom, capture_output=True, shell=True, text=True)

            if cmd_result == 0 or '-c' in cmd_capture.stdout:
                clip_connect = True
            elif cmd_result == 1:
                clip_connect = False
            elif cmd_result > 1:
                clip_connect = False
            self.signal.emit(clip_connect)
            time.sleep(.25)


class CpuInfo(QThread):
    signal = pyqtSignal(list)

    def __init__(self):
        QThread.__init__(self)

    def run(self):
        while True:
            cpu_usage = subprocess.check_output("top -bn1 | grep 'Cpu(s)' | awk '{print $2}' | sed 's/%us,//g'",
                                                shell=True)
            cpu_usage = cpu_usage.decode('utf-8').strip()
            cpu_volt = subprocess.check_output('vcgencmd measure_volts', shell=True)
            cpu_volt = cpu_volt.decode('utf-8')
            cpu_volt = cpu_volt.split('=')[1].strip()
            cpu_temp = subprocess.check_output('vcgencmd measure_temp', shell=True)
            cpu_temp = cpu_temp.decode('utf-8')
            cpu_temp = cpu_temp.split('=')[1].strip()
            self.signal.emit([cpu_usage, cpu_volt, cpu_temp])
            time.sleep(5)


class App(QtWidgets.QStackedWidget, Ui_StackedWidget):

    def __init__(self, parent=None):
        super(App, self).__init__(parent)
        self.setupUi(self)
        self.widget_2.hide()
        self.textBrowser.append("Script Started.\n")

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        self.ip = s.getsockname()[0]
        self.cpu_info = cpuinfo.get_cpu_info()['brand_raw']
        self.sys_label.setText(f"IP: {self.ip} CPU: {self.cpu_info}")


        self.cpu_thread = CpuInfo()
        self.cpu_thread.start()
        self.cpu_thread.signal.connect(self.update_status_bar)

        self.clip_thread = Probe()
        self.clip_thread.start()
        self.clip_thread.signal.connect(self.update_buttons)

        self.deprovision.clicked.connect(self.depro_op)
        self.enter.clicked.connect(self.sn_op)
        self.get_device_info.clicked.connect(self.get_device_info_op)

        self.currently_running = False
        self.last_process_has_error = False

    def depro_op(self):
        self.deprovision.setEnabled(False)
        self.run_thread("Deprovision")

    def sn_op(self):
        self.update_serial.setEnabled(False)
        self.serial_value.setEnabled(False)
        self.run_thread("Serial", serial=self.serial_value)

    def get_device_info_op(self):
        self.get_device_info.setEnabled(False)
        self.textBrowser.append("Checking device info...")
        self.run_thread("Retrieve Serial")

    def run_thread(self, operation, serial=''):

        self.thread = Operations(operation, serial=serial)
        self.thread.currentStatus.connect(self.update_user)
        self.thread.percentageChange.connect(self.progressBar.setValue)
        self.thread.process_error.connect(self.process_error)
        self.thread.currently_running.connect(self.set_thread_running_status)
        self.thread.start()

    def set_thread_running_status(self, state):
        self.currently_running = state

    def process_error(self, state):
        self.last_process_has_error = state

    def update_buttons(self, clip_connected):
        if clip_connected and not self.currently_running:
            self.deprovision.setEnabled(True)
            self.update_serial.setEnabled(True)
            self.get_device_info.setEnabled(True)
            self.serial_value.setEnabled(True)

        else:
            self.deprovision.setEnabled(False)
            self.update_serial.setEnabled(False)
            self.get_device_info.setEnabled(False)
            self.serial_value.setEnabled(False)

    def update_user(self, output):
        self.textBrowser.append(output)
        self.textBrowser.verticalScrollBar().setValue(self.textBrowser.verticalScrollBar().maximum())

    def update_status_bar(self, values):
        self.sys_label.setText(
            f" IP: {self.ip} CPU: {self.cpu_info} @ {values[0]}% Usage Temp: {values[2]} Volt:{values[1]}")


if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    form = App()
    form.showFullScreen()
    app.exec_()
