class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'


    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


    END = '\033[0m'

    @staticmethod
    def disable():
        Colors.RED = ''
        Colors.GREEN = ''
        Colors.YELLOW = ''
        Colors.BLUE = ''
        Colors.MAGENTA = ''
        Colors.CYAN = ''
        Colors.WHITE = ''
        Colors.BOLD = ''
        Colors.UNDERLINE = ''
        Colors.END = ''



def red(text):
    return f"{Colors.RED}{text}{Colors.END}"


def green(text):
    return f"{Colors.GREEN}{text}{Colors.END}"


def yellow(text):
    return f"{Colors.YELLOW}{text}{Colors.END}"


def blue(text):
    return f"{Colors.BLUE}{text}{Colors.END}"


def cyan(text):
    return f"{Colors.CYAN}{text}{Colors.END}"


def bold(text):
    return f"{Colors.BOLD}{text}{Colors.END}"