"""
Command-Line Interface: creates an interface that is used to send
messages as a client.
"""

import curses
from datetime import datetime

__author__ = "spec"
__license__ = "MIT"
__version__ = "0.1"
__status__ = "Development"


class KEYS:

    BACKSPACE = [curses.KEY_BACKSPACE, curses.KEY_DC, 127]
    ENTER = [curses.KEY_ENTER, 10, 13]


class CLI:

    def __init__(self):
        """
        Initialize the command-line interface.
        """
        self.stdscr = curses.initscr()
        self.client = None
        self.max_y, self.max_x = self.stdscr.getmaxyx()
        self.chat_container = curses.newwin(self.max_y - 2, self.max_x, 1, 0)
        self.chat_win = self.chat_container.subwin(self.max_y - 3, self.max_x - 4, 2, 2)
        self.prompt_win = curses.newwin(1, self.max_x, self.max_y - 1, 0)
        self.setup()

    def init_client(self, client):
        """
        Update the client variable once connected.
        :param client: client object to add
        """
        self.client = client

    def uninit_client(self):
        """
        Remove client once disconnected from the server.
        """
        self.add_msg("Connection Lost")
        self.client = None

    def setup(self):
        """
        Perform basic command-line interface setup.
        """
        curses.curs_set(1)
        curses.noecho()
        curses.cbreak()
        # Keypad disabled until scrolling properly implemented
        # self.stdscr.keypad(True)
        self.stdscr.clear()
        self.stdscr.addstr("SecureChat v{}".format(__version__))
        self.chat_container.box()
        self.chat_win.addstr("Welcome to SecureChat!")
        self.chat_win.scrollok(True)
        self.chat_win.setscrreg(0, self.max_y - 5)
        self.prompt_win.addstr("> ")
        self.refresh_all()

    def refresh_chat(self):
        """
        Refresh only the chat box.
        """
        self.chat_container.noutrefresh()
        self.chat_win.noutrefresh()
        curses.doupdate()

    def refresh_prompt(self):
        """
        Refresh only the input prompt.
        """
        self.prompt_win.noutrefresh()
        curses.doupdate()

    def refresh_all(self):
        """
        Refresh everything in the interface.
        """
        self.stdscr.noutrefresh()
        self.chat_container.noutrefresh()
        self.chat_win.noutrefresh()
        self.prompt_win.noutrefresh()
        curses.doupdate()

    def add_msg(self, msg):
        """
        Add a message to the chat box.
        :param msg: message to add
        """
        self.chat_win.addch('\n')
        self.chat_win.addstr("[{}] {}".format(
            datetime.strftime(datetime.now(), "%H:%M"), msg)
        )
        self.refresh_all()

    def submit(self, msg):
        """
        Send a message to the server and add it to the chat box.
        :param msg: message to send
        """
        if len(msg) == 0:
            return
        self.prompt_win.clear()
        self.prompt_win.addstr("> ")
        self.refresh_prompt()
        if not self.client:
            self.add_msg("Error: Not Connected to Server")
            self.refresh_prompt()
            return
        self.add_msg("You: " + msg)
        self.client.send(msg)

    def main(self):
        """
        Main input loop.
        """
        inp = ""
        while True:
            # Get input character
            c = self.stdscr.getch()
            # Enter submits the message
            if c in KEYS.ENTER:
                self.submit(inp)
                inp = ""
            # Delete last character
            elif c in KEYS.BACKSPACE:
                inp = inp[:-1]
                self.prompt_win.clear()
                self.prompt_win.addstr("> " + inp)
                self.refresh_prompt()
            # Scrolling (disabled for now, see stdscr.keypad in setup)
            elif c == curses.KEY_UP:
                self.chat_win.scroll(-1)
                self.refresh_all()
            elif c == curses.KEY_DOWN:
                self.chat_win.scroll(1)
                self.refresh_all()
            # Add input to message if it doesn't exceed max length
            # I will disable the message limit when I get scrolling working properly
            elif len(inp) + 3 < self.max_x:
                k = chr(c)
                inp += k
                self.prompt_win.addstr(k)
                self.refresh_prompt()

    def clean_exit(self):
        """
        Exit cleanly from the interface and reset the command line.
        """
        if self.client:
            if self.client.key:
                self.client.send("!exit")
            self.client.cli = None
        self.stdscr.keypad(False)
        curses.echo()
        curses.nocbreak()
        curses.endwin()
