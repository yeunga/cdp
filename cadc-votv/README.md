#### Canadian Astronomy Data Center Virtual Observatory Table Viewer

Version 2.3
September 2016

ANT Build
The '''build.xml''' file contains tasks for running the qunit JavaScript
Unit Tests, and to install to some other directory.  Run it with
'ant test'.
 
The cadc-votv project is a utility for viewing large tables in the VOTABLE format within a 
Web browser. It is optimized for handling tables ranging in size from 1000 
to 500,000 rows.  It performs extremely well due to the available JavaScript
objects and structures available to modern browsers.

Package Location

The main code for the cadc-votv is located in the src/javascript/cadc.votv.js file,
but all of its dependent files are located in src/javascript as well.

Examples

TODO  

Unit Test

Unit tests are provided by the excellent QUnit package (http://qunitjs.com), and
available tests are in the test directory.  Run all of them with the ant test command
from the top level directory.

Google Project

The OpenCADC project maintains the codebase on GitHub.  It can be found at
https://www.github.com/opencadc.

API Documentation

TODO

Features

The following features are available in the current version of the VOView GUI 
display:

- Optional paging of the rows of the table, or full view in scrollable format.

- Control of column arrangement and display via a contained column picker.

- Arrangement of displayed columns via drag and drop.

- Filtering of rows based on column values.  Filter expressions can be entered for 
each column at the top of the table.

- Sorting of table by column values.  First click sorts the column in descending 
order.  Second click sorts the column in ascending order.

- Row selection, including buttons for selecting all rows and unselecting all rows.
  This feature is enabled via the API, and the list of selected rows can also be 
 returned via an API.
