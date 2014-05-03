=== Synchi ===

Contributors: mdjekic
Donate link: http://projects.djekic.net/synchi
Tags: code, editor, advanced, syntax, highlight, admin, ide, development, codemirror
License: GPLv2
License URI: http://www.gnu.org/licenses/gpl-2.0.html
Requires at least: 2.7
Tested up to: 3.4.2
Stable tag: 5

A full IDE inside your Wordpress! Powerfull IDE features in WP plugin editor,
themes editor, articles HTML editor and text/HTML widgets editor.

== Description ==

Synchi IDE empowers you with syntax highlighting and powerfull IDE features in
WP plugin editor, themes editor and article HTML editor. Plugin is based on
CodeMirror library.

Visit the [project page](http://projects.djekic.net/synchi/) to learn more.

= A full IDE inside WordPress =

Synchi is a full IDE! You no longer need an external code editor, since you
can enjoy code creation experience inside your WordPress, from any location.

No need to leave the plugin/themes editor page for saving files, they are now
opened in tabs for your convenience. You can also create new files and folders,
delete and copy/cut existing files and folders!

You can enjoy syntax highlight and basic IDE features (search/replace,code
formatting, line highlight...) in HTML article editor without conflicts with 
TinyMCE. Full screen is enabled too for both articles and text/HTML widgets
editor. Enjoy!

= Features =

* [syntax highlight](http://en.wikipedia.org/wiki/Syntax_highlighting) for a
  number of programming languages in themes/plugins editor, articles editor
  and text/HTML widgets editor
* [code completion](http://en.wikipedia.org/wiki/Autocomplete) for JavaScript
  and PHP (WordPress functions included)
* editor theming for comfortable coding experience
* full screen editing
* plugins/themes ajax file browser
* tabbed files editing (remembering last opened tabs)
* create/delete/copy/move files and folders via AJAX
* preview image files inside the IDE
* line numbers (with highlighting option)
* line wrapping
* brackets matching
* goto line
* code auto-format
* comment/uncomment code
* search code (with regex search)
* replace code (with regex search)
* Keyboard shortuct for every editor control
* Localization enabled

= Supported programming languages for syntax highlight =

* PHP (.php files)
* JavaScript (.js files)
* CSS (.css files)
* HTML (.html and htm files)
* XML (.xml files)
* MySQL (.sql files)

The code is well documented and understandable. Additional plugin information, 
screenshots and contact information is available at projects.djekic.net

= Localization =

Synchi has localication support. Currently, the IDE is available for:

* English
* Serbian (Српски)

= Author =

[Miloš Đekić](http://milos.djekic.net) is a sofware enthusiast from Belgrade, 
Serbia. He loves to create useful software.

== Installation ==

Before you begin, please make sure jQuery is included (should be WP default). If 
you are by chance using Internet Explorer 6, please do not install this plugin or,
even better, stop using Internet.

= Installation steps =

1. Upload 'synchi' to the '/wp-content/plugins/' directory
1. Activate the plugin through the 'Plugins' menu in WordPress
1. Go to Settings -> Synchi to open the settings
1. Customize your code editing experience and enable/disable Synchi
1. That's it. Enjoy a full IDE inside Wordpress!

== Changelog ==

= 5.0 =
* Added syntax highlight for text widgets in widget editor

= 4.6 =
* Fixed the article editor bugs and optimized loading
* Optimized the settings page and fixed missing theme bug
* Added language support for the article editor and settings
* Localized the article editor and settings to Serbian (sr_RS)

= 4.5 =
* Enabled plugin localization and localized to Serbian (sr_RS)
* Added comment/uncomment code option
* Optimized context menus for tabs and added 'Save' option
* Optimized serialized tabs loading and fixed a transition bug
* Fixed an anoying bug when editing files with huge lines of text
* Fixed a minor bug when attempting to save images from IDE

= 4.4 =
* Added Synchi image preview for previewing images inside the IDE
* Fixed a minor bug in serializing tab positions

= 4.3 =
* Included as a workaround for problems with server settings concerning direct access to scripts other than standard WP entry points
* Added extra settings for indenting with tabs and controlling tab size
* Updated CodeMirror source to version 2.32
* Fixed focusing on first tab when initializing IDE
* Fixed 'Save All' bug when no changes are made

= 4.2 =
* Added Ctrl+Space code completion for php and javascript files (including WP php functions)
* Added matching words highlight
* Added uninstaller to remove junk when removing plugin
* Secured Synchi request handler to ensure that no one but admin can use Synchi
* Ensured plugin/themes editing rights are checked before initializing IDE

= 4.1 =
* Added options to enable/disable Synchi in plugins & themes editor and article editor

= 4.0 =
* Upgraded to a full IDE inside Wordpress for themes and plugins editing
* Enhanced HTML editor for article editing

= 3.3 =
* Added ajax document saving for themes and plugins editor

= 3.2 =
* Added search and search/replace feature
* Added font size setting

= 3.1 =
* Added code auto-formating and indenting
* Added keyboard shortcuts for new features

= 3.0 =
* Added syntax highlight in article editor
* Added line numbers option in editor
* Added brackets matching option in editor
* Added line wrapping option in editor
* Added undo,redo,jump to line controlls
* Added fullscreen editing for themes and plugins

= 2.2 =
* Resolved a small issue when initializing syntax highlight in themes

= 2.1 =
* Added syntax highlight in themes editor.

= 2.0 =
* Added themes for syntax highlight in editor.

= 1.0 =
* First version - syntax highlight on.

== Upgrade Notice ==

Upgrade to a enable syntax highlight in WP text/HTML widgets!

== Screenshots ==

1. Editing footer.php in a theme
2. Ediiting CSS file in fullscreen mode
3. Search dialog
4. Search results
5. Editing a JS file in a plugin
6. Editing article HTML

== Credits ==

To provide a full IDE experience, Synchi uses a number of usefull JavaScript 
libraries made by different authors.

An unmeasured thanks to authors of libraries and jQuery plugins:

* Fantastic [CodeMirror library](http://codemirror.net/) by [Marijn Haverbeke](http://marijnhaverbeke.nl/)
* [jQuery contextMenu Plugin](http://medialize.github.com/jQuery-contextMenu/) by [Rodney Rehm](http://rodneyrehm.de/en/)
* [jQuery Tooltip Plugin](http://bassistance.de/jquery-plugins/jquery-plugin-tooltip/) by [Jörn Zaefferer](http://bassistance.de/)
* [jQuery FileTree](http://www.abeautifulsite.net/blog/2008/03/jquery-file-tree/)
* [Shortcut script](http://bassistance.de/jquery-plugins/jquery-plugin-tooltip/) by [Binny VA](http://blog.binnyva.com/)

Special thanks to users providing valuable feedback and ideas:

* [ebsalberto](http://wordpress.org/support/profile/ebsalberto)
* [eschwartz93](http://wordpress.org/support/profile/eschwartz93)
* [th.meestersx](http://wordpress.org/support/profile/thmeesters)

Synchi IDE plugin is brought to you by [Miloš Đekić](http://milos.djekic.net). If you would like to donate for future
development, please visit the [project page](http://projects.djekic.net/synchi/).