/*
 Copyright (C) 2013 Stephan Haller <nomad@froevel.de>

 This library is free software; you can redistribute it and/or
 modify it under the terms of the GNU Lesser General Public
 License as published by the Free Software Foundation; either
 version 2.1 of the License, or (at your option) any later version.

 See the file COPYING for the full license text.
*/

#include "cookie-permission-manager-preferences-window.h"

#include "cookie-permission-manager.h"


/* Define this class in GObject system */
G_DEFINE_TYPE(CookiePermissionManagerPreferencesWindow,
				cookie_permission_manager_preferences_window,
				GTK_TYPE_DIALOG)

/* Properties */
enum
{
	PROP_0,

	PROP_EXTENSION,

	PROP_LAST
};

static GParamSpec* CookiePermissionManagerPreferencesWindowProperties[PROP_LAST]={ 0, };

/* Private structure - access only by public API if needed */
#define COOKIE_PERMISSION_MANAGER_PREFERENCES_WINDOW_GET_PRIVATE(obj) \
	(G_TYPE_INSTANCE_GET_PRIVATE((obj), TYPE_COOKIE_PERMISSION_MANAGER_PREFERENCES_WINDOW, CookiePermissionManagerPreferencesWindowPrivate))

struct _CookiePermissionManagerPreferencesWindowPrivate
{
	/* Extension related */
	MidoriExtension		*extension;
	sqlite3				*database;

	/* Dialog related */
	GtkWidget			*contentArea;
	GtkListStore		*listStore;
	GtkWidget			*list;
	GtkTreeSelection	*listSelection;
	GtkWidget			*deleteButton;
	GtkWidget			*deleteAllButton;
};

enum
{
	DOMAIN_COLUMN,
	POLICY_COLUMN,
	N_COLUMN
};


/* IMPLEMENTATION: Private variables and methods */
static void _cookie_permission_manager_preferences_window_fill(CookiePermissionManagerPreferencesWindow *self)
{
	CookiePermissionManagerPreferencesWindowPrivate	*priv=self->priv;
	gint											success;
	sqlite3_stmt									*statement=NULL;

	/* Clear tree/list view */
	gtk_list_store_clear(priv->listStore);

	/* Fill list store with policies from database */
	success=sqlite3_prepare_v2(priv->database,
								"SELECT domain, value FROM policies;",
								-1,
								&statement,
								NULL);
	if(statement && success==SQLITE_OK)
	{
		gchar		*domain;
		gint		policy;
		gchar		*policyName;
		GtkTreeIter	iter;

		while(sqlite3_step(statement)==SQLITE_ROW)
		{
			/* Get values */
			domain=(gchar*)sqlite3_column_text(statement, 0);
			policy=sqlite3_column_int(statement, 1);

			switch(policy)
			{
				case COOKIE_PERMISSION_MANAGER_POLICY_ACCEPT:
					policyName=_("Accept");
					break;

				case COOKIE_PERMISSION_MANAGER_POLICY_ACCEPT_FOR_SESSION:
					policyName=_("Accept for session");
					break;

				case COOKIE_PERMISSION_MANAGER_POLICY_BLOCK:
					policyName=_("Block");
					break;

				default:
					policyName=NULL;
					break;
			}

			if(policyName)
			{
				gtk_list_store_append(priv->listStore, &iter);
				gtk_list_store_set(priv->listStore,
									&iter,
									DOMAIN_COLUMN, domain,
									POLICY_COLUMN, policyName,
									-1);
			}
		}
	}
		else g_warning("SQL fails: %s", sqlite3_errmsg(priv->database));

	sqlite3_finalize(statement);
}

/* Open database containing policies for cookie domains */
static gboolean _cookie_permission_manager_preferences_window_open_database(CookiePermissionManagerPreferencesWindow *self)
{
	CookiePermissionManagerPreferencesWindowPrivate	*priv=self->priv;
	const gchar										*configDir;
	gchar											*databaseFile;
	gint											success;

	/* Close any open database */
	if(priv->database) sqlite3_close(priv->database);
	priv->database=NULL;

	/* Build path to database file */
	configDir=midori_extension_get_config_dir(priv->extension);
	if(!configDir)
	{
		g_warning(_("Could not get path to configuration of extension: path is NULL"));
		return(FALSE);
	}

	/* Open database */
	databaseFile=g_build_filename(configDir, COOKIE_PERMISSION_DATABASE, NULL);
	success=sqlite3_open(databaseFile, &priv->database);
	g_free(databaseFile);
	if(success!=SQLITE_OK)
	{
		g_warning(_("Could not open database of extenstion: %s"), sqlite3_errmsg(priv->database));

		if(priv->database) sqlite3_close(priv->database);
		priv->database=NULL;

		return(FALSE);
	}

	_cookie_permission_manager_preferences_window_fill(self);

	/* Set up availability of management buttons */
	gtk_widget_set_sensitive(priv->deleteAllButton, TRUE);

	return(TRUE);
}

/* Selection in list changed */
void _cookie_permission_manager_preferences_changed_selection(CookiePermissionManagerPreferencesWindow *self,
																GtkTreeSelection *inSelection)
{
	gboolean									selected=(gtk_tree_selection_count_selected_rows(inSelection)>0 ? TRUE: FALSE);

	gtk_widget_set_sensitive(self->priv->deleteButton, selected);
}

/* Delete button was clicked on selection */
void _cookie_permission_manager_preferences_on_delete_selection(CookiePermissionManagerPreferencesWindow *self,
																	GtkButton *inButton)
{
	CookiePermissionManagerPreferencesWindowPrivate	*priv=self->priv;
	GList											*rows, *row, *refs=NULL;
	GtkTreeRowReference								*ref;
	GtkTreeModel									*model=GTK_TREE_MODEL(priv->listStore);
	GtkTreeIter										iter;
	GtkTreePath										*path;
	gchar											*domain;
	gchar											*sql;
	gint											success;
	gchar											*error;

	/* Get selected rows in list and create a row reference because
	 * we will modify the model while iterating through selected rows
	 */
	rows=gtk_tree_selection_get_selected_rows(priv->listSelection, &model);
	for(row=rows; row; row=row->next)
	{
		ref=gtk_tree_row_reference_new(model, (GtkTreePath*)row->data);
		refs=g_list_prepend(refs, ref);
	}
	g_list_foreach(rows,(GFunc)gtk_tree_path_free, NULL);
	g_list_free(rows);

	/* Delete each selected row by its reference */
	for(row=refs; row; row=row->next)
	{
		/* Get domain from selected row */
		path=gtk_tree_row_reference_get_path((GtkTreeRowReference*)row->data);
		gtk_tree_model_get_iter(model, &iter, path);
		gtk_tree_model_get(model, &iter, DOMAIN_COLUMN, &domain, -1);

		/* Delete domain from database */
		sql=sqlite3_mprintf("DELETE FROM policies WHERE domain='%q';", domain);
		success=sqlite3_exec(priv->database,
								sql,
								NULL,
								NULL,
								&error);
		if(success!=SQLITE_OK || error)
		{
			if(error)
			{
				g_critical(_("Failed to execute database statement: %s"), error);
				sqlite3_free(error);
			}
				else g_critical(_("Failed to execute database statement: %s"), sqlite3_errmsg(priv->database));
		}
		sqlite3_free(sql);

		/* Delete row from model */
		gtk_list_store_remove(priv->listStore, &iter);
	}
	g_list_foreach(refs,(GFunc)gtk_tree_row_reference_free, NULL);
	g_list_free(refs);
}

/* Delete all button was clicked */
void _cookie_permission_manager_preferences_on_delete_all(CookiePermissionManagerPreferencesWindow *self,
																	GtkButton *inButton)
{
	CookiePermissionManagerPreferencesWindowPrivate	*priv=self->priv;
	gint											success;
	gchar											*error=NULL;
	GtkWidget										*dialog;
	gint											dialogResponse;

	/* Ask user if he really wants to delete all permissions */
	dialog=gtk_message_dialog_new(GTK_WINDOW(self),
									GTK_DIALOG_MODAL,
									GTK_MESSAGE_QUESTION,
									GTK_BUTTONS_YES_NO,
									_("Do you really want to delete all cookie permissions?"),
									NULL);

	gtk_window_set_title(GTK_WINDOW(dialog), _("Delete all cookie permissions?"));
	gtk_window_set_icon_name(GTK_WINDOW(dialog), GTK_STOCK_PROPERTIES);

	gtk_message_dialog_format_secondary_text(GTK_MESSAGE_DIALOG(dialog),
												_("This action will delete all cookie permissions. "
												  "You will be asked for permissions again for each web site visited."));

	dialogResponse=gtk_dialog_run(GTK_DIALOG(dialog));
	gtk_widget_destroy(dialog);

	if(dialogResponse==GTK_RESPONSE_NO) return;

	/* Delete all permission */
	success=sqlite3_exec(priv->database,
							"DELETE FROM policies;",
							NULL,
							NULL,
							&error);

	if(success!=SQLITE_OK || error)
	{
		if(error)
		{
			g_critical(_("Failed to execute database statement: %s"), error);
			sqlite3_free(error);
		}
	}

	/* Re-setup list */
	_cookie_permission_manager_preferences_window_fill(self);
}

/* IMPLEMENTATION: GObject */

/* Finalize this object */
static void cookie_permission_manager_preferences_window_finalize(GObject *inObject)
{
	CookiePermissionManagerPreferencesWindowPrivate	*priv=COOKIE_PERMISSION_MANAGER_PREFERENCES_WINDOW(inObject)->priv;

	/* Dispose allocated resources */
	if(priv->database) sqlite3_close(priv->database);
	priv->database=NULL;

	/* Call parent's class finalize method */
	G_OBJECT_CLASS(cookie_permission_manager_preferences_window_parent_class)->finalize(inObject);
}

/* Set/get properties */
static void cookie_permission_manager_preferences_window_set_property(GObject *inObject,
																		guint inPropID,
																		const GValue *inValue,
																		GParamSpec *inSpec)
{
	CookiePermissionManagerPreferencesWindow	*self=COOKIE_PERMISSION_MANAGER_PREFERENCES_WINDOW(inObject);
	
	switch(inPropID)
	{
		/* Construct-only properties */
		case PROP_EXTENSION:
			self->priv->extension=g_value_get_object(inValue);
			_cookie_permission_manager_preferences_window_open_database(self);
			break;

		default:
			G_OBJECT_WARN_INVALID_PROPERTY_ID(inObject, inPropID, inSpec);
			break;
	}
}

static void cookie_permission_manager_preferences_window_get_property(GObject *inObject,
																		guint inPropID,
																		GValue *outValue,
																		GParamSpec *inSpec)
{
	CookiePermissionManagerPreferencesWindow	*self=COOKIE_PERMISSION_MANAGER_PREFERENCES_WINDOW(inObject);

	switch(inPropID)
	{
		case PROP_EXTENSION:
			g_value_set_object(outValue, self->priv->extension);
			break;

		default:
			G_OBJECT_WARN_INVALID_PROPERTY_ID(inObject, inPropID, inSpec);
			break;
	}
}

/* Class initialization
 * Override functions in parent classes and define properties and signals
 */
static void cookie_permission_manager_preferences_window_class_init(CookiePermissionManagerPreferencesWindowClass *klass)
{
	GObjectClass		*gobjectClass=G_OBJECT_CLASS(klass);

	/* Override functions */
	gobjectClass->finalize=cookie_permission_manager_preferences_window_finalize;
	gobjectClass->set_property=cookie_permission_manager_preferences_window_set_property;
	gobjectClass->get_property=cookie_permission_manager_preferences_window_get_property;

	/* Set up private structure */
	g_type_class_add_private(klass, sizeof(CookiePermissionManagerPreferencesWindowPrivate));

	/* Define properties */
	CookiePermissionManagerPreferencesWindowProperties[PROP_EXTENSION]=
		g_param_spec_object("extension",
								_("Extension instance"),
								_("The Midori extension instance for this extension"),
								MIDORI_TYPE_EXTENSION,
								G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY);

	g_object_class_install_properties(gobjectClass, PROP_LAST, CookiePermissionManagerPreferencesWindowProperties);
}

/* Object initialization
 * Create private structure and set up default values
 */
static void cookie_permission_manager_preferences_window_init(CookiePermissionManagerPreferencesWindow *self)
{
	CookiePermissionManagerPreferencesWindowPrivate		*priv;
	GtkCellRenderer										*renderer;
	GtkTreeViewColumn									*column;
	GtkWidget											*widget;
	gchar												*text;
	gchar												*dialogTitle;
	GtkWidget											*scrolled;
	GtkWidget											*vbox;
	GtkWidget											*hbox;
	gint												width, height;

	priv=self->priv=COOKIE_PERMISSION_MANAGER_PREFERENCES_WINDOW_GET_PRIVATE(self);

	/* Set up default values */
	priv->database=NULL;

	/* Get content area to add gui controls to */
	priv->contentArea=gtk_dialog_get_content_area(GTK_DIALOG(self));
#ifdef HAVE_GTK3
	vbox=gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
	gtk_box_set_homogeneous(GTK_BOX(vbox), FALSE);
#else
	vbox=gtk_vbox_new(FALSE, 0);
#endif

	/* Set up dialog */
	dialogTitle=_("Configure cookie permission");

	gtk_window_set_title(GTK_WINDOW(self), dialogTitle);
	gtk_window_set_icon_name(GTK_WINDOW(self), GTK_STOCK_PROPERTIES);

	sokoke_widget_get_text_size(GTK_WIDGET(self), "M", &width, &height);
	gtk_window_set_default_size(GTK_WINDOW(self), width*52, -1);

	widget=sokoke_xfce_header_new(gtk_window_get_icon_name(GTK_WINDOW(self)), dialogTitle);
	if(widget) gtk_box_pack_start(GTK_BOX(priv->contentArea), widget, FALSE, FALSE, 0);

	gtk_dialog_add_button(GTK_DIALOG(self), GTK_STOCK_CLOSE, GTK_RESPONSE_CLOSE);

	/* Set up description */
	widget=gtk_label_new(NULL);
	text=g_strdup_printf(_("Below is a list of all web sites and the policy set for them. "
							"You can delete policies by marking the entries and clicking on <i>Delete</i>."
							"You will be asked again which policy to follow for this web sites as soon as you visit them."));
	gtk_label_set_markup(GTK_LABEL(widget), text);
	g_free(text);
	gtk_label_set_line_wrap(GTK_LABEL(widget), TRUE);
	gtk_container_add(GTK_CONTAINER(vbox), widget);

	/* Set up model for cookie domain list */
	priv->listStore=gtk_list_store_new(N_COLUMN,
										G_TYPE_STRING,	/* DOMAIN_COLUMN */
										G_TYPE_STRING	/* POLICY_COLUMN */);


	/* Set up cookie domain list */
	priv->list=gtk_tree_view_new_with_model(GTK_TREE_MODEL(priv->listStore));

	priv->listSelection=gtk_tree_view_get_selection(GTK_TREE_VIEW(priv->list));
	gtk_tree_selection_set_mode(priv->listSelection, GTK_SELECTION_MULTIPLE);
	g_signal_connect_swapped(priv->listSelection, "changed", G_CALLBACK(_cookie_permission_manager_preferences_changed_selection), self);

	renderer=gtk_cell_renderer_text_new();
	column=gtk_tree_view_column_new_with_attributes(_("Domain"),
													renderer,
													"text", DOMAIN_COLUMN,
													NULL);
	gtk_tree_view_append_column(GTK_TREE_VIEW(priv->list), column);

	renderer=gtk_cell_renderer_text_new();
	column=gtk_tree_view_column_new_with_attributes(_("Policy"),
													renderer,
													"text", POLICY_COLUMN,
													NULL);
	gtk_tree_view_append_column(GTK_TREE_VIEW(priv->list), column);

	scrolled=gtk_scrolled_window_new(NULL, NULL);
#ifdef HAVE_GTK3
	gtk_scrolled_window_set_min_content_height(GTK_SCROLLED_WINDOW(scrolled), height*10);
#endif
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
	gtk_container_add(GTK_CONTAINER(scrolled), priv->list);
	gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(scrolled), GTK_SHADOW_IN);
	gtk_box_pack_start(GTK_BOX(vbox), scrolled, TRUE, TRUE, 5);

	/* Set up cookie domain list management buttons */
#ifdef HAVE_GTK3
	hbox=gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
	gtk_box_set_homogeneous(GTK_BOX(hbox), FALSE);
#else
	hbox=gtk_hbox_new(FALSE, 0);
#endif

	priv->deleteButton=gtk_button_new_from_stock(GTK_STOCK_DELETE);
	gtk_widget_set_sensitive(priv->deleteButton, FALSE);
	gtk_container_add(GTK_CONTAINER(hbox), priv->deleteButton);
	g_signal_connect_swapped(priv->deleteButton, "clicked", G_CALLBACK(_cookie_permission_manager_preferences_on_delete_selection), self);

	priv->deleteAllButton=gtk_button_new_with_mnemonic(_("Delete _all"));
	gtk_button_set_image(GTK_BUTTON(priv->deleteAllButton), gtk_image_new_from_stock(GTK_STOCK_DELETE, GTK_ICON_SIZE_BUTTON));
	gtk_widget_set_sensitive(priv->deleteAllButton, FALSE);
	gtk_container_add(GTK_CONTAINER(hbox), priv->deleteAllButton);
	g_signal_connect_swapped(priv->deleteAllButton, "clicked", G_CALLBACK(_cookie_permission_manager_preferences_on_delete_all), self);

	gtk_box_pack_start(GTK_BOX(vbox), hbox, TRUE, TRUE, 5);

	/* Finalize setup of content area */
	gtk_container_add(GTK_CONTAINER(priv->contentArea), vbox);
}

/* Implementation: Public API */

/* Create new object */
GtkWidget* cookie_permission_manager_preferences_window_new(MidoriExtension *inExtension)
{
	return(g_object_new(TYPE_COOKIE_PERMISSION_MANAGER_PREFERENCES_WINDOW,
							"extension", inExtension,
							NULL));
}
