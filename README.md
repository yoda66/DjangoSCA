## DjangoSCA

DjangoSCA is a python based Django project source code security auditing system
that makes use of the Django framework itself, the Python Abstract Syntax Tree
(AST) library, and regular expressions.

Django projects are laid out in a directory structure that conforms to a
standard form using known classes, and standard file naming such as
settings.py, urls.py, views.py, and forms.py.

DjangoSCA is designed for the user to pass the root directory of the
Django project as an argument to the program, from which it will
recursively descend through the project files and perform source code
checks on all python source code, and Django template files.

## Credits

DjangoSCA was authored by Joff Thyer with ideas generated in discussion
with both John Strand and Ethan Robish.  In addition, Ethan assisted in
contributing source patches, and additional base rules.  Since the initial
versions, there has been additional community rules contributed also.
