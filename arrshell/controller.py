import datetime

__y = None

def getInstance():
    global __y

    if not __y:
        __y = MainController()

    return __y

class OutputController:
    def __init__(self):
        pass

    def print_debug(self, sender, msg, *args, **kwargs):
        print("[ DEBUG ] [ Module '" + sender.__class__.__name__ + "'] " + str(msg) + "\n", args, kwargs)

    def print_info(self, sender, msg, *args, **kwargs):
        print("[ INFO ] [ Module '" + sender.__class__.__name__ + "'] " + str(msg) + "\n", args, kwargs)

    def print_warning(self, sender, msg, *args, **kwargs):
        print("[ WARNING ] [ Module '" + sender.__class__.__name__ + "'] " + str(msg) + "\n", args, kwargs)

    def print_error(self, sender, msg, *args, **kwargs):
        print("[ ERROR ] [ Module '" + sender.__class__.__name__ + "'] " + str(msg) + "\n", args, kwargs)

class TextWidgetLogController:
    def __init__(self, log_widget=None, log_level=0):
        self.log_widget = log_widget
        # Log Level
        # 0 = DEBUG
        # 1 = INFO
        # 2 = WARNING
        # 3 = ERROR
        self.log_level = log_level

    def set_log_widget(self, widget):
        self.log_widget = widget

    def check_log_level(self, level):
        if self.log_level > level:
            return False
        else:
            return True

    def str_to_log_level(self, string):
        if string.lower() == "debug":
            return 0
        elif string.lower() == "information":
            return 1
        elif string.lower() == "warning":
            return 2
        elif string.lower() == "error":
            return 3

        return -1

    def log_debug(self, msg, *args, **kwargs):
        if not self.check_log_level(self.str_to_log_level("debug")):
            return

        log_msg = ('<span style="color: grey">[ ' +
                    datetime.datetime.now().strftime("%d.%m.%Y - %H:%M:%S") +
                   ' ] [ DEBUG ] ' + str(msg) + '</span>' % args)

        if self.log_widget:
            self.log_widget.append(log_msg)

    def log_info(self, msg, *args, **kwargs):
        if not self.check_log_level(self.str_to_log_level("information")):
            return

        log_msg = ('[ ' + datetime.datetime.now().strftime("%d.%m.%Y - %H:%M:%S") +
                   ' ] [ INFO ] ' + str(msg) % args)

        if self.log_widget:
            self.log_widget.append(log_msg)

    def log_warning(self, msg, *args, **kwargs):
        if not self.check_log_level(self.str_to_log_level("warning")):
            return

        log_msg = ('<b>[ ' +
                   datetime.datetime.now().strftime("%d.%m.%Y - %H:%M:%S") +
                   '] [ WARNING ] ' + str(msg) + '</b>' % args)

        if self.log_widget:
            self.log_widget.append(log_msg)

    def log_error(self, msg, *args, **kwargs):
        if not self.check_log_level(self.str_to_log_level("error")):
            return

        log_msg = ('<b style="color: darkred">[ ' +
                  datetime.datetime.now().strftime("%d.%m.%Y - %H:%M:%S") +
                  ' ] [ ERROR ] ' + str(msg) + '</b>' % args)

        if self.log_widget:
            self.log_widget.append(log_msg)


class MainController:
    def __init__(self):
        self.__output = None
        self.__log = None

    def out(self):
        if not self.__output:
            self.__output = OutputController()   #OutputManager

        return self.__output

    def log(self):
        if not self.__log:
            self.__log = TextWidgetLogController()

        return self.__log
