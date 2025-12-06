Changelog
=========

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
