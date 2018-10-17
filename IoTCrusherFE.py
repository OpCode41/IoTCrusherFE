#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import copy
import subprocess
import io
import os.path
import re
import sys
import json
import ast
from datetime import datetime
from time import sleep
from tkinter import *
from tkinter import messagebox
import tkinter.ttk as ttk
from tkinter import filedialog
import pexpect
import csv

from reportlab.platypus import Paragraph, Table, TableStyle, PageTemplate, BaseDocTemplate, Frame, Image
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.lib import colors


class HyperlinkedImage(Image, object):
    """Image with a hyperlink, adopted from http://stackoverflow.com/a/26294527/304209."""

    def __init__(self, filename, hyperlink=None, width=None, height=None, kind='direct',
                 mask='auto', lazy=1, hAlign='CENTER'):
        """The only variable added to __init__() is hyperlink.

        It defaults to None for the if statement used later.
        """
        super(HyperlinkedImage, self).__init__(filename, width, height, kind, mask, lazy,
                                               hAlign=hAlign)
        self.hyperlink = hyperlink

    def drawOn(self, canvas, x, y, _sW=0):
        if self.hyperlink:  # If a hyperlink is given, create a canvas.linkURL()
            # This is basically adjusting the x coordinate according to the alignment
            # given to the flowable (RIGHT, LEFT, CENTER)
            x1 = self._hAlignAdjust(x, _sW)
            y1 = y
            x2 = x1 + self._width
            y2 = y1 + self._height
            canvas.linkURL(url=self.hyperlink, rect=(x1, y1, x2, y2), thickness=0, relative=1)
        super(HyperlinkedImage, self).drawOn(canvas, x, y, _sW)


def header(canv, doc):
    """Function to render logos and date fo report creation"""
    styles = getSampleStyleSheet()
    style_n = styles['Normal']

    page_num = Paragraph("{}".format(canv.getPageNumber()), style_n)
    page_num.wrap(10, 10)
    page_num.drawOn(canv, doc.width + 95, doc.height + 100)

    canv.saveState()

    shift_left = 144

    p = Paragraph("Report generated on {}".format(datetime.now().date().isoformat()), style_n)
    p.wrap(doc.width + 50, 10)
    p.drawOn(canv, doc.leftMargin + 25 + shift_left, doc.height + 50)

    # Check that media directory exists and contain logos
    cur_path = os.path.dirname(os.path.realpath(__file__))
    media_dir = cur_path + "/media"
    if os.path.isdir(media_dir):
        opcode_logo = media_dir + "/logo.jpg"
        iot_logo = media_dir + "/logo_b.jpg"
        if os.path.exists(opcode_logo):
            # Make clickable logo
            opcode_image = HyperlinkedImage(opcode_logo, "https://opcode41.com/", width=300, height=56)
            opcode_image.drawOn(canv, doc.leftMargin - 50 + shift_left, doc.height + 60)
            # canv.drawInlineImage(opcode_logo, doc.leftMargin - 50 + shift_left, doc.height + 60, width=300, height=56)
        if os.path.exists(iot_logo):
            canv.drawInlineImage(iot_logo, doc.leftMargin - 46, doc.height + 37, width=90, height=90)

    canv.restoreState()


def table_pdf(vulns: dict, pdf_filename: str):
    """Function to create PDF-report for vulerabilities found by IoTCrusher"""
    styles = getSampleStyleSheet()
    style_shell = styles["BodyText"]

    data = []
    datakeys = ["root", "ipaddress", "port", "username", "pwd", "shellprompt"]
    data.append(datakeys)

    for idx, vuln in vulns.items():
        row = []
        for k in datakeys:
            vuln_par = Paragraph(vuln[k].replace('\n', '<br />\n'), style=style_shell)
            row.append(vuln_par)

        data.append(row)

    t = Table(data=data, colWidths=[1 * inch, 1.25 * inch, 0.4 * inch, 1 * inch, 1 * inch, 2.75 * inch], repeatRows=1,
              vAlign="top")
    t.setStyle(TableStyle([
        ('INNERGRID', (0, 0), (-1, -1), 0.25, colors.black),
        ('BOX', (0, 0), (-1, -1), 0.55, colors.black),
        ('VALIGN', (0, 0), (-1, -1), 'TOP')
    ]))

    doc = BaseDocTemplate(pdf_filename, pagesize=letter)

    frame = Frame(doc.leftMargin, doc.topMargin - 60, doc.width, doc.height, id='normal')
    template = PageTemplate(id='test', frames=frame, onPage=header)
    doc.addPageTemplates([template])

    doc.build([t])


def json2xml(json_obj, line_padding=""):
    """Function to create xml-report for vulerabilities found by IoTCrusher"""
    result_list = list()
    json_obj_type = type(json_obj)

    if json_obj_type is list:
        for sub_elem in json_obj:
            result_list.append(json2xml(sub_elem, line_padding))
        return "\n".join(result_list)

    if json_obj_type is dict:
        for tag_name in json_obj:
            sub_obj = json_obj[tag_name]
            tag_repr = tag_name
            if type(tag_name) == int:
                tag_repr = "vuln"
            result_list.append("%s<%s>" % (line_padding, tag_repr))
            result_list.append(json2xml(sub_obj, "\t" + line_padding))
            result_list.append("%s</%s>" % (line_padding, tag_repr))

        return "\n".join(result_list)
    return "%s%s" % (line_padding, json_obj)


def get_iotc_args(exe_path):
    """
    Parsing IoTCrusher arguments from --help output. Defining required arguments.
    :param exe_path: path to IoTCrusher executable
    :return: tuple with list of required arguments and list of strings of --help command output
    """
    cmd = "./IoTCrusher --help"
    p = subprocess.Popen(cmd, cwd=os.path.dirname(exe_path), shell=True, stdout=subprocess.PIPE)
    line_iterator = io.TextIOWrapper(p.stdout, encoding="utf-8")

    arguments = list()
    arg_strings_list = []
    opt_block = False
    for line in line_iterator:
        arguments.append(line)
        if opt_block:
            arg_strings_list.append(line.strip())
        if "optional arguments:" in line:
            opt_block = True

    argstr = "".join(arguments)

    # Required arguments are without [] brackets and placed BEFORE optional arguments
    required_args_re = re.compile("\s-[a-zA-Z]+")
    req_args = required_args_re.findall(argstr.split("optional arguments")[0])
    req_args = [ra.replace(" -", "") for ra in req_args]
    req_args = list(set(req_args))

    return req_args, arg_strings_list


def process_arg_options(opts):
    """
    Finds type of argument and available choices if any.
    Currently supported types:
    str: SOMETEXTINCAPS
    multistr: STRING [STRING ...]
    choice: {STRINGS,IN,FIGURED,BRACKETS}
    multichoice: {C,H,O,I,C,E}, [{C,H,O,I,C,E}, ...]
    :param opts: rest of string without argname
    :rtype: dict
    """

    target = opts.strip()
    last_func_word = None
    choices = None

    # Detect type of opts
    str_family = re.compile("^[A-Z]+")
    choice_family = re.compile("^{[a-zA-Z,]+\}")
    check_str = str_family.search(target)
    check_choice = choice_family.search(target)

    # Check str or choice
    if check_str:
        argtype = 'str'
        last_func_word = check_str.group()
    elif check_choice:
        argtype = 'choice'
        last_func_word = check_choice.group()
        choices = last_func_word[1:-1]  # remove brackets
        choices = [opt.strip() for opt in choices.split(",")]
    else:
        argtype = 'unknown'
        # TODO: possibly should raise an Exception?

    res = {'argtype': argtype}

    if argtype != 'unknown':
        # Check if multi
        multi_family = re.compile("\[[a-zA-Z,}{]+ ...\]")
        check_multi = multi_family.search(target)
        if check_multi:
            multi = True
            last_func_word = check_multi.group()
        else:
            multi = False
        res.update({'multi': multi})

        # Add choices:
        if argtype == 'choice':
            res.update({'choices': choices})

        # Check if help message starts on the same line
        help_text = target.split(last_func_word)[1]
        res.update({'help': help_text.strip()})

    return res


def update_help_text(arg, help_line):
    arg['help'] += help_line
    return arg


def process_argstr_list(arg_strings_list):
    """
    Structuring and organizing IoTCrusher arguments to dictionary.
    Each argument may have name, arg_type, multi, choices, help and default
    :param arg_strings_list: output of running get_iotc_args()[1]
    :return:
    """
    processed_args = {}

    # We shall exclude help argument from GUI
    help_args = ['h', 'help']
    new_arg = None
    args_re = re.compile("^-[a-zA-Z]+")
    for line in arg_strings_list:
        arg_name = args_re.search(line.strip())
        if arg_name:
            # processing of previous arg is finished
            if new_arg:
                processed_args[new_arg['name']] = new_arg
            name = arg_name.group().replace("-", "")
            if name not in help_args:
                new_arg = {'name': name}
                rest = name.join(line.split(name)[1:])
                new_arg.update(process_arg_options(rest))
        else:
            new_arg = update_help_text(new_arg, line)
    # add last processed arg
    processed_args[new_arg['name']] = new_arg

    # check for default values in frames of help
    defaults_re = re.compile("\(default:[^)]*\)")
    for arg_name, properties in processed_args.items():
        if 'help' in properties.keys():
            help_text = properties['help']
            defaults_check = defaults_re.search(help_text)
            if defaults_check:
                defaults_descr = defaults_check.group()
                properties['help'] = help_text.split(defaults_descr)[0]
                defaults_block = defaults_descr[1:-1].split("default:")[1].strip()
                defaults_block = defaults_block.replace("None", "")
                properties['default'] = defaults_block

    return processed_args


# The following code is added to facilitate the Scrolled widgets.
class AutoScroll(object):
    """Configure the scrollbars for a widget."""

    def __init__(self, master):
        #  Rozen. Added the try-except clauses so that this class
        #  could be used for scrolled entry widget for which vertical
        #  scrolling is not supported. 5/7/14.
        try:
            vsb = ttk.Scrollbar(master, orient='vertical', command=self.yview)
        except:
            pass
        hsb = ttk.Scrollbar(master, orient='horizontal', command=self.xview)

        # self.configure(yscrollcommand=_autoscroll(vsb),
        #    xscrollcommand=_autoscroll(hsb))
        try:
            self.configure(yscrollcommand=self._autoscroll(vsb))
        except:
            pass
        self.configure(xscrollcommand=self._autoscroll(hsb))

        self.grid(column=0, row=0, sticky='nsew')
        try:
            vsb.grid(column=1, row=0, sticky='ns')
        except:
            pass
        hsb.grid(column=0, row=1, sticky='ew')

        master.grid_columnconfigure(0, weight=1)
        master.grid_rowconfigure(0, weight=1)

        # Copy geometry methods of master  (taken from ScrolledText.py)

        methods = Pack.__dict__.keys() | Grid.__dict__.keys() | Place.__dict__.keys()

        for meth in methods:
            if meth[0] != '_' and meth not in ('config', 'configure'):
                setattr(self, meth, getattr(master, meth))

    @staticmethod
    def _autoscroll(sbar):
        """Hide and show scrollbar as needed."""

        def wrapped(first, last):
            first, last = float(first), float(last)
            if first <= 0 and last >= 1:
                sbar.grid_remove()
            else:
                sbar.grid()
            sbar.set(first, last)

        return wrapped

    def __str__(self):
        return str(self.master)


def _create_container(func):
    """Creates a ttk Frame with a given master, and use this new frame to
    place the scrollbars and the widget."""

    def wrapped(cls, master, **kw):
        container = ttk.Frame(master)
        return func(cls, container, **kw)

    return wrapped


class ScrolledTreeView(AutoScroll, ttk.Treeview):
    """A standard ttk Treeview widget with scrollbars that will
    automatically show/hide as needed."""

    @_create_container
    def __init__(self, master, **kw):
        ttk.Treeview.__init__(self, master, **kw)
        AutoScroll.__init__(self, master)


class IoTUI(ttk.Frame):
    def __init__(self, top=None):
        """This class configures and populates the toplevel window.
           top is the toplevel containing window."""
        ttk.Frame.__init__(self)
        self.user_settings_path = "./settings.json"
        self.temp_int = IntVar()
        self.temp_str = StringVar()
        self.temp_chk = dict()
        self.iot_response = StringVar()  # Unprocessed output
        self.iot_info = StringVar()  # Info part of output
        self.vuln_identifier = 0  # vuln identifier
        self.iot_vulnes = dict()  # Parsed vulnerabilities
        self.arg_to_trace = None
        self.opt_to_trace = None
        self.trace_cb_name = None
        self.pack(expand=Y, fill=BOTH)

        self.args = None
        self.required = None
        self.exe_path = None
        self.get_exe_path()
        while True:
            try:
                self.get_args_from_help()
                break
            except TypeError:
                ui_conf_path = './ui_config.json'
                ui_config_exists = False

                if os.path.isfile(ui_conf_path):
                    ui_config_exists = True

                new_path = filedialog.askopenfilename(
                    initialdir="./",
                    title="Please specify the path to IoTCrusher executable...",
                )
                if new_path:
                    self.exe_path = new_path
                    if ui_config_exists:
                        with open(ui_conf_path, "r") as ui_conf_file:
                            ui_config = json.load(ui_conf_file)
                            ui_config['exe_path'] = new_path
                    else:
                        ui_config = {'exe_path': new_path}

                    with open(ui_conf_path, "w") as f:
                        json.dump(ui_config, f, indent=4)
                else:
                    print("No location to IoTCrusher was specified")
                    sys.exit(1)

        # TODO: probably should add kinda splashscreen for few seconds?

        # Constructing GUI
        top.geometry("999x709+100+30")
        top.title("IoTCrusher")
        top.resizable(False, False)

        self.status_label = Label(top)
        self.status_label.place(relx=0.01, rely=0.0, height=19, width=120)
        self.status_label.configure(text='Status messages')

        self.status_text = Text(top, font=("systemfixed", 8))
        self.status_text.place(relx=0.01, rely=0.03, relheight=0.59, relwidth=0.47)
        self.status_text.configure(width=374)
        self.status_text.configure(wrap=WORD)

        self.settings_label = Label(top)
        self.settings_label.place(relx=0.49, rely=0.0, height=19, width=60)
        self.settings_label.configure(text='Settings')
        self.settings_label.configure(width=60)

        self.settings_tree = ScrolledTreeView(top)
        self.settings_tree.place(relx=0.49, rely=0.03, relheight=0.59, relwidth=0.22)
        self.settings_tree.heading("#0", anchor="center")
        self.settings_tree.column("#0", width="201")
        self.settings_tree.column("#0", minwidth="20")
        self.settings_tree.column("#0", stretch="1")
        self.settings_tree.column("#0", anchor="w")
        self.settings_tree.tag_configure('required', background='#E8C8C8')

        self.settings_tree.bind("<1>", self.on_click)

        self.vuln_label = Label(top)
        self.vuln_label.place(relx=0.01, rely=0.62, height=19, width=120)
        self.vuln_label.configure(text='Vulnerabilities')

        self.vuln_columns = ('root', 'ipaddress', 'port', 'username', 'pwd', 'shellprompt')
        self.vuln_tree = ScrolledTreeView(top, columns=self.vuln_columns, show="headings")
        self.vuln_tree.place(relx=0.01, rely=0.65, relheight=0.26, relwidth=0.7)

        for c in self.vuln_columns:
            self.vuln_tree.heading(c, text=c)

        self.vuln_tree.column(self.vuln_columns[0], width=101)
        self.vuln_tree.column(self.vuln_columns[1], width=103)
        self.vuln_tree.column(self.vuln_columns[2], width=60)
        self.vuln_tree.column(self.vuln_columns[3], width=112)
        self.vuln_tree.column(self.vuln_columns[4], width=112)
        self.vuln_tree.column(self.vuln_columns[5], width=122)
        self.vuln_tree.bind("<1>", self.show_vuln_tooltip)

        self.setting_options_labeled_frame = LabelFrame(top)
        self.setting_options_labeled_frame.place(relx=0.72, rely=0.01, relheight=0.61, relwidth=0.27)
        self.setting_options_labeled_frame.configure(text='Options')
        self.setting_options_labeled_frame.configure(width=370)

        self.hint_labeled_frame = LabelFrame(top)
        self.hint_labeled_frame.place(relx=0.72, rely=0.64, relheight=0.27, relwidth=0.27)
        self.hint_labeled_frame.configure(text='Hint')

        self.run_button = Button(top, command=self.run_iotcrusher, state='disabled')
        self.run_button.place(relx=0.02, rely=0.93, height=41, width=125)
        self.run_button.configure(text='Run')

        self.save_button = Button(top, command=self.save_settings)
        self.save_button.place(relx=0.16, rely=0.93, height=41, width=125)
        self.save_button.configure(text='Save settings')

        self.load_button = Button(top, command=self.load_settings)
        self.load_button.place(relx=0.3, rely=0.93, height=41, width=125)
        self.load_button.configure(text='Load settings')

        self.export_button = Button(top, command=self.export_results, state='disabled')
        self.export_button.place(relx=0.44, rely=0.93, height=41, width=125)
        self.export_button.configure(text='Export...')

        self.cmd_str_button = Button(top, command=self.cmd_popup)
        self.cmd_str_button.place(relx=0.58, rely=0.93, height=41, width=125)
        self.cmd_str_button.configure(text='Get command')

        self.fill_settings()
        self.check_req_filled()
        self.user_settings = {}

    def get_exe_path(self):
        """Define path for IoTCrusher executable"""
        ui_conf_path = './ui_config.json'
        ui_config_exists = False
        # Option 1: check if user saved custom IoTCrusher location
        if os.path.isfile(ui_conf_path):
            ui_config_exists = True
            with open(ui_conf_path, "r") as ui_conf_file:
                ui_config = json.load(ui_conf_file)
                if 'exe_path' in ui_config.keys():
                    if os.path.isfile(ui_config['exe_path']):
                        self.exe_path = ui_config['exe_path']
                        return

        # Option 2: search IoTCrusher in the same directory
        def_path = "./IoTCrusher"
        if os.path.isfile(def_path):
            self.exe_path = def_path

        # Option 3: let user specify custom IoTCrusher location
        else:
            new_path = filedialog.askopenfilename(
                initialdir="./",
                title="Please specify the path to IoTCrusher executable...",
            )
            if new_path:
                self.exe_path = new_path
                if ui_config_exists:
                    with open(ui_conf_path, "r") as ui_conf_file:
                        ui_config = json.load(ui_conf_file)
                        ui_config['exe_path'] = new_path
                else:
                    ui_config = {'exe_path': new_path}

                with open(ui_conf_path, "w") as f:
                    json.dump(ui_config, f, indent=4)
            else:
                print("Wrong location to IoTCrusher was specified")
                sys.exit(1)

    def get_args_from_help(self):
        """Obtain structured dictionary with arguments from --help output"""
        self.required, arg_str_list = get_iotc_args(self.exe_path)
        self.args = process_argstr_list(arg_str_list)

    def fill_settings(self):
        """Fill listbox with IoTCrusher arguments: required in the beginning and alphabetically sorted others"""

        # Separate required args
        req_args = []
        opt_args = []

        for arg_name, properties in self.args.items():
            if arg_name in self.required:
                req_args.append(properties)
            else:
                opt_args.append(properties)

        # Sort args alphabetically
        req_args = sorted(req_args, key=lambda x: x['name'].lower())
        opt_args = sorted(opt_args, key=lambda x: x['name'].lower())

        # Add to UI:
        for idx, arg in enumerate(req_args):
            self.settings_tree.insert("", idx, text=arg['name'], values=arg['name'], tags=('required', arg['name']))

        shift = len(req_args)
        for idx, arg in enumerate(opt_args):
            self.settings_tree.insert("", idx + shift, text=arg['name'], values=arg['name'], tags=(arg['name'],))

    def check_req_filled(self):
        """Run button should be disabled if required fields are blank"""
        allow_run = True
        for arg_name in self.required:
            if 'default' in self.args[arg_name].keys() and self.args[arg_name]['default']:
                continue
            if 'selected' not in self.args[arg_name].keys():
                allow_run = False
                break

            if self.args[arg_name]['selected'] == [""]:
                allow_run = False
                break

        state = 'normal' if allow_run else 'disabled'
        self.run_button.config(state=state)

        self.after(200, self.check_req_filled)

    def on_text_change(self, *_):
        """Callback to deliver real-time updates for corresponding fields on user text input"""
        self.args[self.arg_to_trace]['selected'] = [self.temp_str.get()]

    def on_checkbox_select(self, *_):
        """Callback to deliver real-time updates for corresponding fields on user checkbox input"""
        self.args[self.arg_to_trace]['selected'] = [k for k, v in self.temp_chk.items() if v.get()]

    def on_radio_select(self, *_):
        """Callback to deliver real-time updates for corresponding fields on user radiobuttons input"""
        self.args[self.arg_to_trace]['selected'] = [self.args[self.arg_to_trace]['choices'][self.temp_int.get()]]

    def on_click(self, event, refresh=False):
        """Rendering Options and Hint blocks when user selects argument from Settings block"""
        if refresh:
            selection = self.settings_tree.selection()
            if len(selection) == 0:
                return
            item = self.settings_tree.selection()[0]
        else:
            region = self.settings_tree.identify("region", event.x, event.y)
            if region != "heading":
                item = self.settings_tree.identify_row(event.y)
            else:
                return
        if len(self.settings_tree.selection()) > 0:
            self.settings_tree.selection_remove(self.settings_tree.selection()[0])
        self.settings_tree.selection_add(item)
        clicked_setting = self.settings_tree.item(item)
        setting = clicked_setting['values'][0]
        self.arg_to_trace = setting
        self.setting_options_labeled_frame.configure(text=setting)

        properties = self.args[setting]

        hint_msg = Label(self.hint_labeled_frame, anchor="nw", wraplength=245, justify=LEFT)
        hint_msg.place(relx=0.01, rely=0.01, relwidth=0.97, relheight=0.97)
        hint_text = properties['help']
        if 'default' in properties.keys() and properties['default']:
            hint_text += "\n\nDefault: {}".format(properties['default'])

        hint_msg.configure(text=hint_text)

        # Clearing current content of options block
        for child in self.setting_options_labeled_frame.winfo_children():
            child.destroy()

        if properties['argtype'] == 'choice':
            if properties['multi']:

                # Checkboxes
                self.temp_chk = dict()
                for idx, choice_opt in enumerate(properties['choices']):
                    self.temp_chk[choice_opt] = BooleanVar()
                    opt = Checkbutton(self.setting_options_labeled_frame, anchor="w",
                                      variable=self.temp_chk[choice_opt], command=self.on_checkbox_select)
                    opt.place(relx=0.03, rely=0.02 + 0.05 * idx, relheight=0.04, relwidth=0.7, h=5)
                    opt.configure(text=choice_opt)
                    if 'selected' in properties.keys():
                        # mark checked corresponding choices
                        if choice_opt in properties['selected']:
                            opt.select()

                    elif 'default' in properties.keys():
                        try:
                            checked_opts = ast.literal_eval(properties['default'])
                        except ValueError:
                            checked_opts = properties['default']
                        if choice_opt in checked_opts:
                            opt.select()
            else:
                # Radiobuttons
                self.temp_int.set(-1)
                for idx, choice_opt in enumerate(properties['choices']):
                    opt = Radiobutton(self.setting_options_labeled_frame, anchor="w", variable=self.temp_int,
                                      value=idx, command=self.on_radio_select)
                    opt.place(relx=0.03, rely=0.02 + 0.05 * idx, relheight=0.04, relwidth=0.7, h=5)
                    opt.configure(text=choice_opt)
                    # opt.deselect()
                    if 'selected' in properties.keys():
                        # mark checked corresponding choices
                        if choice_opt in properties['selected']:
                            opt.select()

                    elif 'default' in properties.keys():
                        if choice_opt in properties['default']:
                            opt.select()
        else:
            # String and Multi-Strings
            try:
                # Python 3.5
                if len(self.temp_str.trace_vinfo()):
                    self.temp_str.trace_vdelete("w", self.trace_cb_name)
                    self.temp_str.set("")

            except AttributeError:
                # Python 3.6+
                if len(self.temp_str.trace_info()):
                    self.temp_str.trace_remove("write", self.trace_cb_name)
                    self.temp_str.set("")

            if 'selected' in properties.keys():
                self.temp_str.set(properties['selected'][0])

            elif 'default' in properties.keys():
                self.temp_str.set(properties['default'])

            opt = Entry(self.setting_options_labeled_frame, textvariable=self.temp_str)
            opt.place(relx=0.03, rely=0.02, relwidth=0.9)

            try:
                # Python 3.5
                self.trace_cb_name = self.temp_str.trace_variable('w', self.on_text_change)
            except AttributeError:
                # Python 3.6+
                self.trace_cb_name = self.temp_str.trace_add('write', self.on_text_change)

        return "break"

    def prepare_cmd(self):
        """Construct command with arguments for IoTCrusher executing relying on Settings entered by user"""
        args_to_run = []
        for arg_name, properties in self.args.items():
            arg_block = ""
            if 'selected' in properties.keys():
                assert type(properties['selected']) == list
                arg_block += " ".join(properties['selected'])

            elif 'default' in properties.keys() and properties['default']:
                if properties['multi']:
                    try:
                        checked_opts = ast.literal_eval(properties['default'])
                        checked_opts = " ".join(checked_opts)
                    except ValueError:
                        checked_opts = properties['default']
                    except TypeError:
                        print("{} default: {}".format(arg_name, properties['default']))
                        raise
                    arg_block += checked_opts
                else:
                    arg_block += properties['default']

            if arg_block:
                arg_block = "-" + arg_name + " " + arg_block
                args_to_run.append(arg_block)

        cmd = "IoTCrusher " + " ".join(args_to_run)

        return cmd
    
    def cmd_popup(self):
        """Rendering pop-up window with command with arguments for IoTCrusher executing
        relying on Settings entered by user.
        """
        def simulate_ctrl_a(e):
            """Ctr+A callback"""
            e.widget.tag_add("sel", "1.0", "end")

        cmd = self.prepare_cmd()

        w = Toplevel(self)
        w.bind_class("Text", "<Control-a>", simulate_ctrl_a)
        w.wm_title("Terminal command")
        w.geometry("400x250+200+100")
        w.resizable(False, False)

        cmd_d = Text(w, wrap=WORD, exportselection=0)
        cmd_d.place(x=5, y=5, height=220, width=380)
        cmd_d.insert('end', cmd)
    
    @staticmethod
    def warn_data_missing():
        """Pop-up alert on 2nd+ run attempt"""
        ans = messagebox.askokcancel("Warning", "There are vulnerability results. Clicking OK will remove the "
                                                "results and start a new scan. Click Cancel to save.")
        return ans

    def run_iotcrusher(self):
        """Running IoTCrusher with user's args using pexpect library.
        Multiprocessing + PIPE is not the case here, since we need real-time output in UI
        """
        if self.vuln_identifier > 0:
            answer = self.warn_data_missing()
            if not answer:
                return

        # Clear vuln treeview and reset vuln counter
        for row in self.vuln_tree.get_children():
            self.vuln_tree.delete(row)
        self.vuln_identifier = 0

        self.export_button.config(state='disabled')

        self.status_text.delete(1.0, END)
        self.status_text.update_idletasks()

        cmd = self.prepare_cmd()
        cmd += " -AppMode FrontEndCmdLine"  # Need for xml output format

        cmd = cmd.split()
        arguments = cmd[1:]
        child = pexpect.spawn(self.exe_path, args=arguments, cwd=os.path.dirname(self.exe_path), timeout=3000)
        child.setwinsize(1000, 50)
        proceed = False
        proceed_type = None
        vuln_msg = None
        status_msg = None
        decor_re = re.compile("\\x1b\[[0-9]+m")
        xml_re = re.compile("<[a-z/_]+>")

        for line in child:
            processed_line = re.sub(decor_re, "", line.decode('utf-8'))
            tags = xml_re.findall(processed_line)

            if proceed:
                if proceed_type == 'msg':
                    # Ending of message block
                    if '</msg>' in tags:
                        status_msg += processed_line.split("</msg>")[0]
                        self.process_status_msg(status_msg)
                        proceed = False
                        proceed_type = None

                    # Message block continues
                    else:
                        status_msg += processed_line

                elif proceed_type == 'vuln':
                    # Ending of vulnerability block
                    if "</vuln>" in tags:
                        vuln_msg += processed_line.split("</vuln>")[0]
                        self.process_vuln_msg(vuln_msg)
                        proceed = False
                        proceed_type = None

                    # Vulnerability block continues
                    else:
                        vuln_msg += processed_line

            else:
                # Beginning of vulnerability block
                if "<vuln>" in tags:
                    # print("VULN")
                    vuln_msg = processed_line.split("<vuln>")[1]
                    # case of one-line vuln xml description
                    if "</vuln>" in tags:
                        vuln_msg = vuln_msg.split("</vuln>")[0]
                        self.process_vuln_msg(vuln_msg)
                    else:
                        proceed = True
                        proceed_type = "vuln"

                # Simply remove other tags
                elif "<msg>" in tags:
                    status_msg = processed_line.split("<msg>")[1]
                    # case of one-line status message:
                    if "</msg>" in tags:
                        status_msg = status_msg.split("</msg>")[0]
                        self.process_status_msg(status_msg)
                    else:
                        proceed = True
                        proceed_type = "msg"

                else:
                    if '<xml>' in tags or '</xml>' in tags:
                        continue
        # TODO: send message to status bar
        child.close()

    def process_status_msg(self, line):
        """Inserting Status message to UI"""
        xml_re = re.compile("<[a-z/_]+>")
        status_msg = re.sub(xml_re, "", line) + '\n'
        self.status_text.insert(END, status_msg)
        self.status_text.see(END)
        self.status_text.update_idletasks()

    def process_vuln_msg(self, line):
        """Function to process vulnerability message and add to widget"""
        line += "x"
        vuln_info = {}
        tags = ['root', 'ipaddress', 'port', 'username', 'pwd']
        for tag in tags:
            tag_re = re.compile('<{}>.*</{}>'.format(tag, tag), re.S)
            info = tag_re.search(line)
            msg = info.group() if info else ""
            if msg:
                msg = msg.split('<{}>'.format(tag))[1].split('</{}>'.format(tag))[0]
            vuln_info[tag] = msg

        sh_prmpt_re = re.compile('<shellprompt>.*</shellprompt>', re.S)
        sh_prmpt = sh_prmpt_re.search(line)
        msg = sh_prmpt.group() if sh_prmpt else ""
        if msg:
            msg = msg.split('<shellprompt>')[1].split('</shellprompt>')[0]
        vuln_info['shellprompt'] = msg

        self.iot_vulnes[self.vuln_identifier] = copy.deepcopy(vuln_info)

        vuln_info['shellprompt'] = vuln_info['shellprompt'][:18].strip() + '...'
        tk_values = [str(vuln_info[t]) for t in tags + ['shellprompt']]
        self.vuln_tree.insert('', END, values=tk_values, tags=self.vuln_identifier)
        self.vuln_tree.update_idletasks()
        self.vuln_identifier += 1

        self.export_button.config(state='normal')

        return tk_values

    def show_vuln_tooltip(self, event):
        """Popup with Vulnerability description"""
        _iid = self.vuln_tree.identify_row(event.y)
        vuln = self.vuln_tree.item(_iid)

        try:
            vuln_id = vuln['tags'][0]
            vuln_dict = self.iot_vulnes[vuln_id]
        except IndexError:
            return

        w = Toplevel(self)
        w.wm_title("Vulnerability description")
        w.geometry("600x400+200+100")
        w.resizable(False, False)

        root_l = Label(w, anchor="e")
        root_l.place(x=2, y=8, height=18, width=100)
        root_l.configure(text='root: ')
        root_d = Text(w, wrap=WORD)
        root_d.place(x=105, y=8, height=20, width=285)
        root_d.insert('end', vuln_dict['root'])
        root_d.configure(state='disabled')
        root_d.bind('<1>', lambda e: root_d.focus_set())

        ipaddress_l = Label(w, anchor="e")
        ipaddress_l.place(x=2, y=30, height=18, width=100)
        ipaddress_l.configure(text='ipaddress: ')
        ipaddress_d = Text(w, wrap=WORD)
        ipaddress_d.place(x=105, y=30, height=20, width=285)
        ipaddress_d.insert('end', vuln_dict['ipaddress'])
        ipaddress_d.configure(state='disabled')
        ipaddress_d.bind('<1>', lambda e: ipaddress_d.focus_set())

        port_l = Label(w, anchor="e")
        port_l.place(x=2, y=52, height=18, width=100)
        port_l.configure(text='port: ')
        port_d = Text(w, wrap=WORD)
        port_d.place(x=105, y=52, height=20, width=285)
        port_d.insert('end', vuln_dict['port'])
        port_d.configure(state='disabled')
        port_d.bind('<1>', lambda e: port_d.focus_set())

        username_l = Label(w, anchor="e")
        username_l.place(x=2, y=74, height=18, width=100)
        username_l.configure(text='username: ')
        username_d = Text(w, wrap=WORD)
        username_d.place(x=105, y=74, height=20, width=285)
        username_d.insert('end', vuln_dict['username'])
        username_d.configure(state='disabled')
        username_d.bind('<1>', lambda e: username_d.focus_set())

        pwd_l = Label(w, anchor="e")
        pwd_l.place(x=2, y=96, height=18, width=100)
        pwd_l.configure(text='pwd: ')
        pwd_d = Text(w, wrap=WORD)
        pwd_d.place(x=105, y=96, height=20, width=285)
        pwd_d.insert('end', vuln_dict['pwd'])
        pwd_d.configure(state='disabled')
        pwd_d.bind('<1>', lambda e: pwd_d.focus_set())

        shellprompt_l = Label(w, anchor="e")
        shellprompt_l.place(x=2, y=118, height=18, width=100)
        shellprompt_l.configure(text='shellprompt: ')
        shellprompt_d = Text(w, wrap=WORD)
        shellprompt_d.place(x=105, y=118, height=270, width=480)
        vsb = Scrollbar(w, orient="vertical", command=shellprompt_d.yview)
        shellprompt_d.configure(yscrollcommand=vsb.set)
        vsb.pack(side='right', fill='y')
        shellprompt_d.insert('end', vuln_dict['shellprompt'])
        shellprompt_d.config(state='disabled')
        shellprompt_d.bind('<1>', lambda e: shellprompt_d.focus_set())

    def save_settings(self):
        settings_file = filedialog.asksaveasfilename(
            initialdir="./",
            title="Select settings file...",
            filetypes=(("settings files", "*.json"), ("all files", "*.*"))
        )

        if settings_file:
            with open(settings_file, "w") as f:
                json.dump(self.args, f, indent=4)

    def load_settings(self):
        settings_file = filedialog.askopenfilename(
            initialdir="./",
            title="Select settings file...",
            filetypes=(("settings files", "*.json"), ("all files", "*.*"))
        )

        if settings_file:
            try:
                with open(settings_file, "r") as f:
                    self.args = json.load(f)
                    self.on_click(None, True)
            except Exception as err:
                msg = "ERROR: Choosed settings file has incorrect format"
                self.status_text.insert(END, msg)
                print("ERROR: {}".format(str(err)))

    def export_results(self):
        """Saving Vulnerabilities to file as report"""
        path_to_file = filedialog.asksaveasfilename(
            initialdir="./",
            title="Select filename and format",
            filetypes=(
                ("plain txt", "*.txt"),
                ("xml", "*.xml"),
                ("csv", "*.csv"),
                ("pdf", "*.pdf"),
            )
        )

        if path_to_file:
            filename, file_ext = os.path.splitext(path_to_file)
            if file_ext == ".txt":
                with open(path_to_file, "w") as txtf:
                    content = ""
                    for vuln_id in range(self.vuln_identifier):
                        vuln = self.iot_vulnes[vuln_id]
                        content += "Vuln-" + str(vuln_id) + "\n"
                        for key, value in vuln.items():
                            # since shellprompt is the only multiline text
                            if key == 'shellprompt':
                                content += key + ": "
                                descr = value.split("\n")
                                if len(descr) > 1:
                                    content += descr[0] + "\n"
                                    for line in descr[1:]:
                                        content += " "*13 + line + "\n"
                                else:
                                    content += value + "\n"
                            else:
                                content += str(key) + ": " + str(value) + "\n"
                        content += "-"*80 + "\n"
                        content += "\n"
                    txtf.write(content)

            elif file_ext == ".xml":
                with open(path_to_file, "w") as xmlf:
                    prepr = {"Vulnerabilities": self.iot_vulnes}
                    xml_content = json2xml(prepr)
                    xmlf.write(xml_content)

            elif file_ext == ".csv":
                with open(path_to_file, "w") as csvf:
                    prepr = [vuln for v_id, vuln in self.iot_vulnes.items()]
                    headers = prepr[0].keys()
                    writer = csv.DictWriter(csvf, headers)
                    writer.writeheader()
                    writer.writerows(prepr)
            elif file_ext == ".pdf":
                table_pdf(self.iot_vulnes, path_to_file)


if __name__ == '__main__':
    root = Tk()
    main_window = IoTUI(root)
    root.mainloop()
