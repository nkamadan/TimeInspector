import gi
import ldd
gi.require_version("Gtk", "3.0")
from gi.repository import Gtk



class Handlers():
    def __init__(self,main):
        self.self_of_main = main
        
    def on_filechooserbutton_file_set(self, widget):
        print(widget.get_filename())
        file_path = widget.get_filename()
        Main.populateTreeView(self.self_of_main,file_path)

class Main:
    def __init__(self):
        gladeFile = "deneme2.glade"
        self.builder = Gtk.Builder()
        self.builder.add_from_file(gladeFile)
        self.builder.connect_signals(Handlers(self))

        self.treeview = self.builder.get_object("treeView")
        self.pathListStore = Gtk.ListStore(str,str,str,str)
        window = self.builder.get_object("window1")
        menu = self.builder.get_object("menu")
        self.populateTreeView("none")

        self.fileChooser = self.builder.get_object("fileChooser")
        window.connect("delete-event", Gtk.main_quit)
        window.set_title("Deependency")
        window.show()

    def populateTreeView(self,fp):
        if(fp == "none"):
            print("Gtk Python Glade")
        else:
            file_path = fp
            pass1 = ldd.find_shared_libs(file_path)
            pass2 = ldd.privilege(pass1)
            pass3 = ldd.search_for_imported_symbols(pass1,fp)
            pass4 = ["Yes", "No","No"]
            for elem in range(0,len(pass1)):
                self.pathListStore.append([pass1[elem],pass2[elem],pass3[elem],pass4[elem]])

            treeview_columns = ['Binary/Library', 'Privilege','Imported Functions',"Rdtsc"]
            for col_num, name in enumerate(treeview_columns):
                # align text in column cells of row (0.0 left, 0.5 center, 1.0 right)
                rendererText = Gtk.CellRendererText(xalign=0.5, editable=False)
                column = Gtk.TreeViewColumn(name ,rendererText, text=col_num)
                self.treeview.set_model(self.pathListStore)
                # center the column titles in first row
                column.set_alignment(0.2)
                # make all the column reorderable, resizable and sortable
                column.set_sort_column_id(col_num)
                column.set_reorderable(True)
                column.set_resizable(True)
                self.treeview.append_column(column)

if __name__ == '__main__':
    main = Main()
    Gtk.main()