Changelog
=========

0.4.3
----------


Added
~~~~~~~~~~~~~~~~~~~~~

- Improved dependency cycle detection

- Allow stdin for install update and install order

- Add stdin for commands that consume addon naems directly

- Add skill and explain install order



Fixed
~~~~~~~~~~~~~~~~~~~~~

- (db) Fix db creation



Documentation
~~~~~~~~~~~~~~~~~~~~~

- Update changelog


0.4.2
----------


Added
~~~~~~~~~~~~~~~~~~~~~

- Hide commands on default for agent commands

- Dedpulicate agent output



Fixed
~~~~~~~~~~~~~~~~~~~~~

- Fix failing unit test

- Failing unit test



Documentation
~~~~~~~~~~~~~~~~~~~~~

- Update changelog


0.4.1
----------


Added
~~~~~~~~~~~~~~~~~~~~~

- Add documentation commands

- Add path parameter for shorting long paths

- Docs support multi-addon bundle



Fixed
~~~~~~~~~~~~~~~~~~~~~

- Use res.partner as example

- Fix unit test

- Windows test



Documentation
~~~~~~~~~~~~~~~~~~~~~

- Update changelog


0.4.0
----------


Added
~~~~~~~~~~~~~~~~~~~~~

- Start working on agent mode

- Improve agent capabilities

- Add api models for better parsing available odoo models

- New find-model-extensions command

- Add summary

- Add command for getting model views

- Improved right management for agents

- New command validate-addon-change

- Cleanup after refactoring

- Add command to get installed addons

- Add uninstall command

- New addon-info command

- Improved structure

- New runtime inspection and review commands

- Adapt new rjntime inspection for agent mode

- Add mutation policy

- Edit config command

- New right management, db risk level removed

- Use next port when http port is blocked



Fixed
~~~~~~~~~~~~~~~~~~~~~

- Improve test parsing for agents

- Better error output

- Integration tests

- Unit test

- Fix for windows

- Integration test



Documentation
~~~~~~~~~~~~~~~~~~~~~

- Update changelog

- Update doc

- Update readme

- Use common odoo model

- Add example for model and view inspection

- Update doc for agent commands



Refactor
~~~~~~~~~~~~~~~~~~~~~

- Part 1

- Part 2

- Part 3

- Part 4

- Part 5

- Part 6



Miscellaneous
~~~~~~~~~~~~~~~~~~~~~

- Fix package

- Add missing logs


0.3.0
----------


Added
~~~~~~~~~~~~~~~~~~~~~

- Add allow_unsafe=True is required to execute code

- Several small improvements

- Add doctor and other usefull cli commands, rewrite documentation



Fixed
~~~~~~~~~~~~~~~~~~~~~

- Fix broken unit test

- Unit test and mpy



Documentation
~~~~~~~~~~~~~~~~~~~~~

- Add changelog

- Update README



Miscellaneous
~~~~~~~~~~~~~~~~~~~~~

- Fix mypy oduit

- Fix mypy and pre-commit


0.2.2
----------


Added
~~~~~~~~~~~~~~~~~~~~~

- Improved print-config and .oduit.toml support for examples

- Get odoo version

- Improve json odoo version output

- (cli) Improved list-addons with include/exclude filters and new list-manifest and list-manifest-values command



Testing
~~~~~~~~~~~~~~~~~~~~~

- Add integration test



Miscellaneous
~~~~~~~~~~~~~~~~~~~~~

- Add integration test to github action

- Fix path

- Fix pre-commit and add missing pytest

- Fix test discovery

- Change working dir

- Improve integration test

- Fix oduit.toml location

- Add integration test for odoo 18


0.2.1
----------


Added
~~~~~~~~~~~~~~~~~~~~~

- Better json output



Fixed
~~~~~~~~~~~~~~~~~~~~~

- Exit code for install and update cli

- Cli test returns results and correct exit code

- Mypy parser fixes

- Mypy parser fixes



Miscellaneous
~~~~~~~~~~~~~~~~~~~~~

- Update ruff


0.2.0
----------


Added
~~~~~~~~~~~~~~~~~~~~~

- Improved list-addons command

- Addon path manager and manifest_collection has been added

- Add tree option

- Add depth parameter

- New parameter

- Add manifestoo-core

- Detect odoo series

- Add sorting modules

- Do not repeat version in tree

- Improved tree layout

- List-missing added to cli

- Exclude addons beginning with test_ and allow to exclude core and enterprise addons



Fixed
~~~~~~~~~~~~~~~~~~~~~

- Codepends



Documentation
~~~~~~~~~~~~~~~~~~~~~

- Add new classes



Miscellaneous
~~~~~~~~~~~~~~~~~~~~~

- Fix static type checker mypy


0.1.7
----------


Added
~~~~~~~~~~~~~~~~~~~~~

- Short json parameter

- (cli) More parameters

- Improve lang option



Fixed
~~~~~~~~~~~~~~~~~~~~~

- (cli) Add error message



Documentation
~~~~~~~~~~~~~~~~~~~~~

- Improve readme and doc, adding more urls to project

- Fix api doc links

- Improve doc with no-index



Miscellaneous
~~~~~~~~~~~~~~~~~~~~~

- Fix doc build

- Fix link

- Fix pre-commit


0.1.6
----------


Added
~~~~~~~~~~~~~~~~~~~~~

- (config) Improved get_odoo_params_list



Documentation
~~~~~~~~~~~~~~~~~~~~~

- Automatically generate changelog through cliff

- Add pypi badge


0.1.5
----------


Fixed
~~~~~~~~~~~~~~~~~~~~~

- Db params need a underscore


0.1.4
----------


Added
~~~~~~~~~~~~~~~~~~~~~

- Better help screen for cli tool

- (db) Move drop_db into own function


0.1.3
----------


Fixed
~~~~~~~~~~~~~~~~~~~~~

- List-db was printed twice



Testing
~~~~~~~~~~~~~~~~~~~~~

- Fix path on windows


0.1.2
----------


Added
~~~~~~~~~~~~~~~~~~~~~

- (db) List db added



Fixed
~~~~~~~~~~~~~~~~~~~~~

- Path for windows

- Use a more robust approach


0.1.1
----------


Added
~~~~~~~~~~~~~~~~~~~~~

- (db) Allow drop_db and create_db without sudo



Documentation
~~~~~~~~~~~~~~~~~~~~~

- Fix build

- Fix documentation



Testing
~~~~~~~~~~~~~~~~~~~~~

- Update codecov



Miscellaneous
~~~~~~~~~~~~~~~~~~~~~

- Add codecov workflow

- Add readthedocs.yml

- Fix pre-commit

- Fix actions

- Add codecov badge


0.1.0
----------


Fixed
~~~~~~~~~~~~~~~~~~~~~

- Not working parameter in install removed



Documentation
~~~~~~~~~~~~~~~~~~~~~

- Add cli doc



Refactor
~~~~~~~~~~~~~~~~~~~~~

- Remove obsolete function from config_loader



Miscellaneous
~~~~~~~~~~~~~~~~~~~~~

- Initial release

- Pre-commit and readme cleanup
