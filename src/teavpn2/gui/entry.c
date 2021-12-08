
#include <gtk/gtk.h>

static void print_hello(GtkWidget *widget, gpointer data)
{
	(void) widget;
	(void) data;
	g_print("Hello World\n");
}

static void activate(GtkApplication *app, gpointer user_data)
{
	GtkWidget *window;
	GtkWidget *button;
	GtkWidget *button_box;

	(void) user_data;
	window = gtk_application_window_new(app);
	gtk_window_set_title(GTK_WINDOW(window), "TeaVPN2");
	gtk_window_set_default_size(GTK_WINDOW(window), 200, 200);

	button_box = gtk_button_box_new(GTK_ORIENTATION_HORIZONTAL);
	gtk_container_add(GTK_CONTAINER(window), button_box);

	button = gtk_button_new_with_label("Click Me");
	g_signal_connect(button, "clicked", G_CALLBACK(print_hello), NULL);
	gtk_container_add(GTK_CONTAINER(button_box), button);

	gtk_widget_show_all(window);
}

int gui_entry(int argc, char **argv)
{
	GtkApplication *app;
	int status;

	app = gtk_application_new("org.gtk.example", G_APPLICATION_FLAGS_NONE);
	g_signal_connect(app, "activate", G_CALLBACK(activate), NULL);
	status = g_application_run(G_APPLICATION(app), argc, argv);
	g_object_unref(app);

	return status;
}
