// =============================================================================
// File: synchi_editor.js
// Version: 2.0
// 
// Enables synchi editor for articles
// =============================================================================

var synchi_editor = false;
var synchi_mode = 'n/a'; // html,visual
var synchi_fullscreen = false;
var synchi_controls = false;
var synchi_lock = false;

/**
 * Performs a synchi control action
 *
 * @param control string control name
 */
function synchi_Control(control) {
    switch(control) {
        case 'search':
            CodeMirror.commands.find(synchi_editor.editor);
            break;
        case 'find_prev':
            CodeMirror.commands.findPrev(synchi_editor.editor);
            break;
        case 'find_next':
            CodeMirror.commands.findNext(synchi_editor.editor);
            break;
        case 'search_replace':
            CodeMirror.commands.replaceAll(synchi_editor.editor);
            break;
        case 'undo':
            synchi_editor.editor.undo();
            break;
        case 'redo':
            synchi_editor.editor.redo();
            break;
        case 'goto':
            synchi_editor.gotoLine();
            break;
        case 'format':
            synchi_editor.editor.indentSelection('smart');
            break;
        case 'indent_left':
            synchi_editor.editor.indentSelection('subtract');
            break;
        case 'indent_right':
            synchi_editor.editor.indentSelection('add'); 
            break;
        case 'fullscreen':
            var container = $('#wp-content-editor-container');
            if(container.hasClass('synchi_fullscreen')) {
                container.removeClass('synchi_fullscreen');
                synchi_fullscreen = false;
            }
            else {
                container.addClass('synchi_fullscreen');
                synchi_fullscreen = true;
                synchi_editor.focus();
            }
            break;
    }
}

/**
 * Initializes article editor with syntax highlight
 */
function synchi_initArticleEditor() {
    // check if controls already rendered
    if(synchi_controls) {
        // handle controls
        synchi_controls.original = $("#ed_toolbar").clone(true);
        synchi_controls.parent = $("#ed_toolbar").parent();
        
        // init the editor
        synchi_editor = $("#content").parent().synchi('file.html');
        
        // swap controls
        $("#ed_toolbar").remove();
        synchi_controls.parent.prepend(synchi_controls.synchi);
        
        return;
    }
    
    // enable lock
    synchi_lock = true;
    
    // get editor controls
    synchi_call('get_editor_controls', {}, function(response) {        
        // handle the controls menu
        synchi_controls = {};
        synchi_controls.original = $("#ed_toolbar").clone(true);
        synchi_controls.synchi = response.result;
        synchi_controls.parent = $("#ed_toolbar").parent();
        
        // init the editor
        synchi_editor = $("#content").parent().synchi('file.html');
        
        // swap controls
        $("#ed_toolbar").remove();
        synchi_controls.parent.prepend(synchi_controls.synchi);
        
        // release lock
        synchi_lock = false;
    });    
}

/**
 * Switches the editor between modes
 * 
 * @param mode switch to
 * @param element caller
 */
function synchi_switch(mode,element) {
    // check lock
    if(synchi_lock) return false;
    
    // enable lock
    synchi_lock = true;
    
    // check mode
    switch(mode) {
        case 'visual':if(synchi_mode != 'visual') {
            // clear editor
            if(synchi_editor) {
                synchi_editor.editor.toTextArea();
                synchi_editor = false;

                // swap controls
                $("#ed_toolbar").remove();
                synchi_controls.parent.prepend(synchi_controls.original);

                // set mode
                synchi_mode = 'visual';
            }
        }break;
        case 'html':if(synchi_mode != 'html') {
            // init synchi editor
            synchi_initArticleEditor();
            // set mode
            synchi_mode = 'html';
        }break;
    }
    
    setTimeout(function(){
        // release lock
        synchi_lock = false;
    
        // perform default behaviour
        switchEditors.switchto(element);
    },256);
    
    return false;
}

/**
 * Performs initializations on page load
 */
function synchi_onLoad() {
    synchi_hideMessage();
    
    // check TinyMCE
    if(typeof(tinyMCE) == "undefined") return;
    
    // determine mode
    synchi_mode = (tinyMCE.activeEditor == null || tinyMCE.activeEditor.isHidden() != false) ? 'html' : 'visual';
    
    // init editor if HTML mode active
    if(synchi_mode == 'html') setTimeout(synchi_initArticleEditor, 54);
    
    // override switch button clicks
    $('#content-tmce').click(function(){return synchi_switch('visual',this);});
    $('#content-html').click(function(){return synchi_switch('html',this);});
    
    // bind click events to line numbers
    $('.CodeMirror-gutter-text pre').live('click',function(){
        if(!synchi_editor) return;
        var line = Number($.trim($(this).text()))-1;
        if(!synchi_editor.editor.getLineHandle(line)) return;
        synchi_editor.editor.setCursor(line,0);
        synchi_editor.editor.setSelection(
            {line:line, ch:0},
            {line:line+1, ch:0}
        );
        synchi_editor.editor.focus();
    });
    
    // bind key shortcuts
    var bindings = {
        'Ctrl+f' : function(event){ 
            if(synchi_editor) synchi_Control('search'); 
        },
        'Ctrl+r' : function(event){ 
            if(synchi_editor) synchi_Control('search_replace'); 
        },
        'Ctrl+left' : function(event){ 
            if(synchi_editor) synchi_Control('find_prev'); 
        },
        'Ctrl+right' : function(event){ 
            if(synchi_editor) synchi_Control('find_next'); 
        },
        'Alt+Shift+left' : function(event){ 
            if(synchi_editor) synchi_Control('indent_left'); 
        },
        'Alt+Shift+right' : function(event){ 
            if(synchi_editor) synchi_Control('indent_right'); 
        },
        'Alt+Shift+f' : function(event){ 
            if(synchi_editor) synchi_Control('format'); 
        },
        'Ctrl+z' : function(event){ 
            if(synchi_editor) synchi_Control('undo'); 
        },
        'Ctrl+y' : function(event){ 
            if(synchi_editor) synchi_Control('redo'); 
        },
        'Ctrl+g' : function(event){ 
            if(synchi_editor) synchi_Control('goto'); 
        },
        'Alt+return' : function(event){ 
            if(synchi_editor) synchi_Control('fullscreen'); 
        }
    };
    for(var index in bindings) shortcut.add(index,bindings[index]);
}

// On Load
$(function(){ 
    synchi_showLoadingMessage(synchi_labels['Initializing Synchi IDE']);
    setTimeout(synchi_onLoad, 1000); 
});