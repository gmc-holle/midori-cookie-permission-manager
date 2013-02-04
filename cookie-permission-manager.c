/*
 Copyright (C) 2013 Stephan Haller <nomad@froevel.de>

 This library is free software; you can redistribute it and/or
 modify it under the terms of the GNU Lesser General Public
 License as published by the Free Software Foundation; either
 version 2.1 of the License, or (at your option) any later version.

 See the file COPYING for the full license text.
*/

#include "cookie-permission-manager.h"

#include <errno.h>

/* Define this class in GObject system */
G_DEFINE_TYPE(CookiePermissionManager,
				cookie_permission_manager,
				G_TYPE_OBJECT)

/* Properties */
enum
{
	PROP_0,

	PROP_EXTENSION,
	PROP_APPLICATION,

	PROP_LAST
};

static GParamSpec* CookiePermissionManagerProperties[PROP_LAST]={ 0, };

/* Private structure - access only by public API if needed */
#define COOKIE_PERMISSION_MANAGER_GET_PRIVATE(obj) \
	(G_TYPE_INSTANCE_GET_PRIVATE((obj), TYPE_COOKIE_PERMISSION_MANAGER, CookiePermissionManagerPrivate))

struct _CookiePermissionManagerPrivate
{
	/* Extension related */
	MidoriExtension					*extension;
	MidoriApp						*application;
	sqlite3							*database;

	/* Session related */
	void(*oldRequestQueued)(SoupSessionFeature *inFeature, SoupSession *inSession, SoupMessage *inMessage);
	void(*oldRequestUnqueued)(SoupSessionFeature *inFeature, SoupSession *inSession, SoupMessage *inMessage);

	/* Cookie jar related */
	SoupSession						*session;
	SoupCookieJar					*cookieJar;
	SoupSessionFeatureInterface		*featureIface;
	gint							cookieJarChangedID;
};


/* IMPLEMENTATION: Private variables and methods */
static void _cookie_permission_manager_error(CookiePermissionManager *self, const gchar *inReason)
{
	GtkWidget		*dialog;

	/* Show confirmation dialog for undetermined cookies */
	dialog=gtk_message_dialog_new(NULL,
									GTK_DIALOG_MODAL,
									GTK_MESSAGE_ERROR,
									GTK_BUTTONS_OK,
									_("A fatal error occurred which prevents "
									  "the cookie permission manager extension "
									  "to continue. You should disable it."),
									NULL);

	gtk_window_set_title(GTK_WINDOW(dialog), _("Error in cookie permission manager extension"));
	gtk_window_set_icon_name(GTK_WINDOW (dialog), "midori");

	gtk_message_dialog_format_secondary_text(GTK_MESSAGE_DIALOG(dialog),
												"%s:\n%s",
												_("Reason"),
												inReason);

	gtk_dialog_run(GTK_DIALOG(dialog));

	/* Free up allocated resources */
	gtk_widget_destroy(dialog);
}

/* Open database containing policies for cookie domains.
 * Create database and setup table structure if it does not exist yet.
 */
static void _cookie_permission_manager_open_database(CookiePermissionManager *self)
{
	CookiePermissionManagerPrivate	*priv=self->priv;
	const gchar						*configDir;
	gchar							*databaseFile;
	gchar							*error=NULL;
	gint							success;
	sqlite3_stmt					*statement=NULL;

	/* Close any open database */
	if(priv->database) sqlite3_close(priv->database);
	priv->database=NULL;

	/* Build path to database file */
	configDir=midori_extension_get_config_dir(priv->extension);
	if(!configDir)
	{
		g_warning(_("Could not get path to configuration of extension: path is NULL"));

		_cookie_permission_manager_error(self, _("Could not get path to configuration of extension."));
		return;
	}
	
	if(katze_mkdir_with_parents(configDir, 0700))
	{
		g_warning(_("Could not create configuration folder for extension: %s"), g_strerror(errno));

		_cookie_permission_manager_error(self, _("Could not create configuration folder for extension."));
		return;
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

		_cookie_permission_manager_error(self, _("Could not open database of extension."));
		return;
	}

	/* Create table structure if it does not exist */
	success=sqlite3_exec(priv->database,
							"CREATE TABLE IF NOT EXISTS "
							"policies(domain text, value integer);",
							NULL,
							NULL,
							&error);

	if(success==SQLITE_OK)
	{
		success=sqlite3_exec(priv->database,
								"CREATE UNIQUE INDEX IF NOT EXISTS "
								"domain ON policies (domain);",
								NULL,
								NULL,
								&error);
	}

	if(success==SQLITE_OK)
	{
		success=sqlite3_exec(priv->database,
								"PRAGMA journal_mode=TRUNCATE;",
								NULL,
								NULL,
								&error);
	}

	if(success!=SQLITE_OK || error)
	{
		_cookie_permission_manager_error(self, _("Could not set up database structure of extension."));

		if(error)
		{
			g_critical(_("Failed to execute database statement: %s"), error);
			sqlite3_free(error);
		}

		sqlite3_close(priv->database);
		priv->database=NULL;
		return;
	}

	// Delete all cookies allowed only in one session
	g_message("Delete all cookies from cookieJar @%p only allowed for one session", priv->cookieJar);

	success=sqlite3_prepare_v2(priv->database,
								"SELECT domain FROM policies WHERE value=? ORDER BY domain DESC;",
								-1,
								&statement,
								NULL);
	if(statement && success==SQLITE_OK) success=sqlite3_bind_int(statement, 1, COOKIE_PERMISSION_MANAGER_POLICY_ACCEPT_FOR_SESSION);
	if(statement && success==SQLITE_OK)
	{
		while(sqlite3_step(statement)==SQLITE_ROW)
		{
			gchar		*domain=(gchar*)sqlite3_column_text(statement, 0);
			GSList		*cookies, *cookie;

#ifdef HAVE_LIBSOUP_2_40_0
			SoupURI		*uri;

			uri=soup_uri_new(NULL);
			soup_uri_set_host(uri, domain);
			cookies=soup_cookie_jar_get_cookie_list(priv->cookieJar, uri, TRUE);
			for(cookie=cookies; cookie; cookie->next)
			{
				soup_cookie_jar_delete_cookie(priv->cookieJar, (SoupCookie*)cookie->data);
				g_message("Deleted temporary cookie: domain=%s, name=%s",
							soup_cookie_get_domain((SoupCookie*)cookie->data),
							soup_cookie_get_name((SoupCookie*)cookie->data));
			}
			soup_cookies_free(cookies);
			soup_uri_free(uri);
#else
			cookies=soup_cookie_jar_all_cookies(priv->cookieJar);
			for(cookie=cookies; cookie; cookie=cookie->next)
			{
				if(soup_cookie_domain_matches((SoupCookie*)cookie->data, domain))
				{
					soup_cookie_jar_delete_cookie(priv->cookieJar, (SoupCookie*)cookie->data);
					g_message("Deleted temporary cookie: domain=%s, name=%s",
								soup_cookie_get_domain((SoupCookie*)cookie->data),
								soup_cookie_get_name((SoupCookie*)cookie->data));
				}
			}
			soup_cookies_free(cookies);
#endif
		}
	}
		else g_warning("SQL fails: %s", sqlite3_errmsg(priv->database));

	sqlite3_finalize(statement);
}

/* Get policy for cookies from domain */
static gint _cookie_permission_manager_get_policy(CookiePermissionManager *self, SoupCookie *inCookie)
{
	CookiePermissionManagerPrivate	*priv=self->priv;
	sqlite3_stmt					*statement=NULL;
	gchar							*domain;
	gint							error;
	gint							policy=COOKIE_PERMISSION_MANAGER_POLICY_UNDETERMINED;

	/* Check for open database */
	g_return_val_if_fail(priv->database, COOKIE_PERMISSION_MANAGER_POLICY_UNDETERMINED);

	/* Lookup policy for cookie domain in database */
	domain=g_strdup(soup_cookie_get_domain(inCookie));
	if(*domain=='.') *domain='%';
g_message("%s: cookieDomain=%s -> policy=%d", __func__, domain, policy);

	error=sqlite3_prepare_v2(priv->database,
								"SELECT domain, value FROM policies WHERE domain LIKE ? ORDER BY domain DESC;",
								-1,
								&statement,
								NULL);
	if(statement && error==SQLITE_OK) error=sqlite3_bind_text(statement, 1, domain, -1, NULL);
	if(statement && error==SQLITE_OK)
	{
		while(policy==COOKIE_PERMISSION_MANAGER_POLICY_UNDETERMINED &&
				sqlite3_step(statement)==SQLITE_ROW)
		{
			gchar		*policyDomain=(gchar*)sqlite3_column_text(statement, 0);

g_message("%s: checking domain %s against %s", __func__, domain, policyDomain);
			if(soup_cookie_domain_matches(inCookie, policyDomain))
			{
				policy=sqlite3_column_int(statement, 1);
g_message("%s: Found domain in database -> policy=%d", __func__, policy);
			}
		}
	}
		else g_warning("SQL fails: %s", sqlite3_errmsg(priv->database));

	sqlite3_finalize(statement);
	g_free(domain);

	return(policy);
}

/* Ask user what to do with cookies from domain(s) which were neither marked accepted nor blocked */
static gint _cookie_permission_manager_sort_cookies_by_domain(SoupCookie *inLeft, SoupCookie *inRight)
{
	const gchar		*domainLeft=soup_cookie_get_domain(inLeft);
	const gchar		*domainRight=soup_cookie_get_domain(inRight);
	gint			result;

	if(*domainLeft=='.') domainLeft++;
	if(*domainRight=='.') domainRight++;

	return(g_ascii_strcasecmp(domainLeft, domainRight));
}

static GSList* _cookie_permission_manager_get_number_domains_and_cookies(CookiePermissionManager *self,
																			GSList *inCookies,
																			gint *ioNumberDomains,
																			gint *ioNumberCookies)
{
	GSList			*sortedList, *iter;
	gint			domains, cookies;
	const gchar		*lastDomain=NULL;
	const gchar		*cookieDomain;

	/* Make copy and sort cookies in new list */
	sortedList=g_slist_copy(inCookies);

	/* Sort cookies by domain to prevent a doman counted multiple times */
	sortedList=g_slist_sort(sortedList, (GCompareFunc)_cookie_permission_manager_sort_cookies_by_domain);

	/* Iterate through list and count domains and cookies */
	domains=cookies=0;
	for(iter=sortedList; iter; iter=iter->next)
	{
		cookieDomain=soup_cookie_get_domain((SoupCookie*)iter->data);

		if(!lastDomain || g_ascii_strcasecmp(lastDomain, cookieDomain)!=0)
		{
			domains++;
			lastDomain=cookieDomain;
		}

		cookies++;
	}

	/* Store counted numbers to final variables */
	if(ioNumberDomains) *ioNumberDomains=domains;
	if(ioNumberCookies) *ioNumberCookies=cookies;

	/* Return the copied but sorted cookie list. Caller is responsible to free
	 * this list with g_slist_free
	 */
	return(sortedList);
}

static gint _cookie_permission_manager_ask_for_policy(CookiePermissionManager *self,
														GSList *inUnknownCookies)
{
	CookiePermissionManagerPrivate	*priv=self->priv;
	GtkWidget						*dialog;
	GtkWidget						*button;
	gchar							*message;
	gint							numberDomains, numberCookies;
	gint							response;
	GSList							*sortedCookies;

	/* Build message to display */
	sortedCookies=_cookie_permission_manager_get_number_domains_and_cookies(self,
																			inUnknownCookies,
																			&numberDomains,
																			&numberCookies);
																			
	if(numberDomains==1)
	{
		const gchar					*cookieDomain=soup_cookie_get_domain((SoupCookie*)sortedCookies->data);

		if(*cookieDomain=='.') cookieDomain++;
		
		if(numberCookies>1)
			message=g_strdup_printf(_("The website %s wants to store %d cookies."), cookieDomain, numberCookies);
		else
			message=g_strdup_printf(_("The website %s wants to store a cookie."), cookieDomain);
	}
		else
		{
			message=g_strdup_printf(_("Multiple websites want to store %d cookies in total."), numberCookies);
		}

	/* Show confirmation dialog for undetermined cookies */
	dialog=gtk_message_dialog_new(NULL,
									GTK_DIALOG_MODAL,
									GTK_MESSAGE_QUESTION,
									GTK_BUTTONS_NONE,
									message,
									NULL);

	gtk_window_set_title(GTK_WINDOW(dialog), _("Confirm storing cookie"));
	gtk_window_set_icon_name(GTK_WINDOW (dialog), "midori");

	button=gtk_dialog_add_button(GTK_DIALOG(dialog), _("Accept"), COOKIE_PERMISSION_MANAGER_POLICY_ACCEPT);
	gtk_button_set_image(GTK_BUTTON(button), gtk_image_new_from_stock(GTK_STOCK_APPLY, GTK_ICON_SIZE_BUTTON));

	gtk_dialog_add_button(GTK_DIALOG(dialog), _("Accept for this session"), COOKIE_PERMISSION_MANAGER_POLICY_ACCEPT_FOR_SESSION);

	button=gtk_dialog_add_button(GTK_DIALOG(dialog), _("Deny"), COOKIE_PERMISSION_MANAGER_POLICY_BLOCK);
	gtk_button_set_image(GTK_BUTTON(button), gtk_image_new_from_stock(GTK_STOCK_CANCEL, GTK_ICON_SIZE_BUTTON));

	response=gtk_dialog_run(GTK_DIALOG(dialog));

	/* Store user's decision in database if it is not a temporary block.
	 * We use the already sorted list of cookies to prevent multiple
	 * updates of database for the same domain. This sorted list is a copy
	 * to avoid a reorder of cookies
	 */
	if(response>=0)
	{
		const gchar					*lastDomain=NULL;
		GSList						*cookies;

		/* Iterate through cookies and store decision for each domain once */
		for(cookies=sortedCookies; cookies; cookies=cookies->next)
		{
			SoupCookie				*cookie=(SoupCookie*)cookies->data;
			const gchar				*cookieDomain=soup_cookie_get_domain(cookie);

			if(*cookieDomain=='.') cookieDomain++;

			/* Store decision if new domain found while iterating through cookies */
			if(!lastDomain || g_ascii_strcasecmp(lastDomain, cookieDomain)!=0)
			{
				gchar	*sql;
				gchar	*error=NULL;
				gint	success;

				sql=sqlite3_mprintf("INSERT OR REPLACE INTO policies (domain, value) VALUES ('%q', %d);",
										cookieDomain,
										response);
				success=sqlite3_exec(priv->database, sql, NULL, NULL, &error);
				if(success!=SQLITE_OK) g_warning("SQL fails: %s", error);
				if(error) sqlite3_free(error);
				sqlite3_free(sql);

				lastDomain=cookieDomain;
			}
		}
	}

	/* Free up allocated resources */
	g_free(message);
	g_slist_free(sortedCookies);
	gtk_widget_destroy(dialog);

	/* Return user's selection */
	return(response>=0 ? response : COOKIE_PERMISSION_MANAGER_POLICY_BLOCK);
}

/* A cookie was changed outside a request (e.g. Javascript) */
static void _cookie_permission_manager_on_cookie_changed(CookiePermissionManager *self,
															SoupCookie *inOldCookie,
															SoupCookie *inNewCookie,
															SoupCookieJar *inCookieJar)
{
	GSList			*newCookies;
	gint			newCookiePolicy;
	const gchar		*domain;

	/* Do not check changed cookies because they must have been allowed before.
	 * Also do not check removed cookies because they are removed ;)
	 */
	if(inNewCookie==NULL || inOldCookie) return;

	/* New cookie is a new cookie so check */
	switch(_cookie_permission_manager_get_policy(self, inNewCookie))
	{
		case COOKIE_PERMISSION_MANAGER_POLICY_BLOCK:
			soup_cookie_jar_delete_cookie(inCookieJar, inNewCookie);
			break;

		case COOKIE_PERMISSION_MANAGER_POLICY_UNDETERMINED:
			newCookies=g_slist_prepend(NULL, inNewCookie);
			newCookiePolicy=_cookie_permission_manager_ask_for_policy(self, newCookies);
			if(newCookiePolicy==COOKIE_PERMISSION_MANAGER_POLICY_BLOCK)
			{
				/* Free cookie because it should be blocked */
				soup_cookie_jar_delete_cookie(inCookieJar, inNewCookie);
			}
				else
				{
					/* Cookie was accept so do nothing (it is already added) */
				}
			g_slist_free(newCookies);
			break;

		case COOKIE_PERMISSION_MANAGER_POLICY_ACCEPT:
		case COOKIE_PERMISSION_MANAGER_POLICY_ACCEPT_FOR_SESSION:
			break;
	}
}

/* We received the HTTP headers of the request and it contains cookie-managing headers */
static void _cookie_permission_manager_process_set_cookie_header(SoupMessage *inMessage, gpointer inUserData)
{
gchar *_uri=soup_uri_to_string(soup_message_get_uri(inMessage), FALSE);
g_message("%s: message=%p, uri=%s", __func__, (void*)inMessage, _uri);
g_free(_uri);

	g_return_if_fail(IS_COOKIE_PERMISSION_MANAGER(inUserData));

	CookiePermissionManager			*self=COOKIE_PERMISSION_MANAGER(inUserData);
	CookiePermissionManagerPrivate	*priv=self->priv;
	GSList							*newCookies, *cookie;
	GSList							*unknownCookies=NULL, *acceptedCookies=NULL;
	gboolean						unknownMultipleDomains;
	SoupURI							*firstParty;
	SoupCookieJarAcceptPolicy		cookiePolicy;
	gint							unknownCookiesPolicy;

	/* If policy is to deny all cookies return immediately */
	cookiePolicy=soup_cookie_jar_get_accept_policy(priv->cookieJar);
	if(cookiePolicy==SOUP_COOKIE_JAR_ACCEPT_NEVER) return;

	/* Iterate through cookies in response and check if they should be
	 * blocked (remove from cookies list) or accepted (added to cookie jar).
	 * If we could not determine what to do collect these cookies and
	 * ask user
	 */
	newCookies=soup_cookies_from_response(inMessage);
	firstParty=soup_message_get_first_party(inMessage);
	unknownMultipleDomains=FALSE;
	for(cookie=newCookies; cookie; cookie=cookie->next)
	{
		switch(_cookie_permission_manager_get_policy(self, cookie->data))
		{
			case COOKIE_PERMISSION_MANAGER_POLICY_BLOCK:
				soup_cookie_free(cookie->data);
				break;

			case COOKIE_PERMISSION_MANAGER_POLICY_ACCEPT:
			case COOKIE_PERMISSION_MANAGER_POLICY_ACCEPT_FOR_SESSION:
				if((cookiePolicy==SOUP_COOKIE_JAR_ACCEPT_NO_THIRD_PARTY &&
						firstParty!=NULL &&
						firstParty->host &&
						soup_cookie_domain_matches(cookie->data, firstParty->host)) ||
						cookiePolicy==SOUP_COOKIE_JAR_ACCEPT_ALWAYS)
				{
					acceptedCookies=g_slist_prepend(acceptedCookies, cookie->data);
				}
					else soup_cookie_free(cookie->data);
				break;

			case COOKIE_PERMISSION_MANAGER_POLICY_UNDETERMINED:
			default:
				if((cookiePolicy==SOUP_COOKIE_JAR_ACCEPT_NO_THIRD_PARTY &&
						firstParty!=NULL &&
						firstParty->host &&
						soup_cookie_domain_matches(cookie->data, firstParty->host)) ||
						cookiePolicy==SOUP_COOKIE_JAR_ACCEPT_ALWAYS)
				{
					unknownCookies=g_slist_prepend(unknownCookies, cookie->data);
				}
					else soup_cookie_free(cookie->data);
				break;
		}
	}

	/* Prepending an item to list is the fastest method but the order of cookies
	 * is reversed now and may be added to cookie jar in the wrong order. So we
	 * need to reverse list now of both - undetermined and accepted cookies
	 */
	unknownCookies=g_slist_reverse(unknownCookies);
	acceptedCookies=g_slist_reverse(acceptedCookies);

	/* Ask user for his decision what to do with cookies whose policy is undetermined
	 * But only ask if there is any undetermined one
	 */
	if(g_slist_length(unknownCookies)>0)
	{
		unknownCookiesPolicy=_cookie_permission_manager_ask_for_policy(self, unknownCookies);
		if(unknownCookiesPolicy==COOKIE_PERMISSION_MANAGER_POLICY_ACCEPT ||
			unknownCookiesPolicy==COOKIE_PERMISSION_MANAGER_POLICY_ACCEPT_FOR_SESSION)
		{
			/* Add accepted undetermined cookies to cookie jar */
			for(cookie=unknownCookies; cookie; cookie=cookie->next)
			{
				soup_cookie_jar_add_cookie(priv->cookieJar, (SoupCookie*)cookie->data);
			}
		}
			else
			{
				/* Free cookies because they should be blocked */
				for(cookie=unknownCookies; cookie; cookie=cookie->next)
				{
					soup_cookie_free((SoupCookie*)cookie->data);
				}
			}
	}

	/* Add accepted cookies to cookie jar */
	for(cookie=acceptedCookies; cookie; cookie=cookie->next)
	{
		soup_cookie_jar_add_cookie(priv->cookieJar, (SoupCookie*)cookie->data);
	}

	/* Free list of cookies */
	g_slist_free(unknownCookies);
	g_slist_free(acceptedCookies);
	g_slist_free(newCookies);
}

/* A request was started and is in queue now */
static void _cookie_permission_manager_request_queued(SoupSessionFeature *inFeature, SoupSession *inSession, SoupMessage *inMessage)
{
	/* Get class instance */
	CookiePermissionManager		*manager=g_object_get_data(G_OBJECT(inFeature), "cookie-permission-manager");

	/* Listen to "got-headers" signals and register handlers for
	 * checking cookie-managing headers in HTTP stream
	 */
	soup_message_add_header_handler(inMessage,
										"got-headers",
										"Set-Cookie",
										G_CALLBACK(_cookie_permission_manager_process_set_cookie_header),
										manager);

	soup_message_add_header_handler(inMessage,
										"got-headers",
										"Set-Cookie2",
										G_CALLBACK(_cookie_permission_manager_process_set_cookie_header),
										manager);
}

/* Request has loaded and was unqueued */
static void _cookie_permission_manager_request_unqueued(SoupSessionFeature *inFeature, SoupSession *inSession, SoupMessage *inMessage)
{
	/* Stop listening to HTTP stream */
	g_signal_handlers_disconnect_by_func(inMessage, _cookie_permission_manager_process_set_cookie_header, inFeature);
}

/* IMPLEMENTATION: GObject */

/* Finalize this object */
static void cookie_permission_manager_finalize(GObject *inObject)
{
	CookiePermissionManagerPrivate	*priv=COOKIE_PERMISSION_MANAGER(inObject)->priv;

	/* Dispose allocated resources */
	if(priv->database) sqlite3_close(priv->database);
	priv->database=NULL;

	g_signal_handler_disconnect(priv->cookieJar, priv->cookieJarChangedID);

	priv->featureIface->request_queued=priv->oldRequestQueued;
	priv->featureIface->request_unqueued=priv->oldRequestUnqueued;

	g_object_steal_data(G_OBJECT(priv->cookieJar), "cookie-permission-manager");

	/* Call parent's class finalize method */
	G_OBJECT_CLASS(cookie_permission_manager_parent_class)->finalize(inObject);
}

/* Set/get properties */
static void cookie_permission_manager_set_property(GObject *inObject,
													guint inPropID,
													const GValue *inValue,
													GParamSpec *inSpec)
{
	CookiePermissionManager		*self=COOKIE_PERMISSION_MANAGER(inObject);
	
	switch(inPropID)
	{
		/* Construct-only properties */
		case PROP_EXTENSION:
			self->priv->extension=g_value_get_object(inValue);
			_cookie_permission_manager_open_database(self);
			break;

		case PROP_APPLICATION:
			self->priv->application=g_value_get_object(inValue);
			break;

		default:
			G_OBJECT_WARN_INVALID_PROPERTY_ID(inObject, inPropID, inSpec);
			break;
	}
}

static void cookie_permission_manager_get_property(GObject *inObject,
													guint inPropID,
													GValue *outValue,
													GParamSpec *inSpec)
{
	CookiePermissionManager		*self=COOKIE_PERMISSION_MANAGER(inObject);

	switch(inPropID)
	{
		case PROP_EXTENSION:
			g_value_set_object(outValue, self->priv->extension);
			break;

		case PROP_APPLICATION:
			g_value_set_object(outValue, self->priv->application);
			break;

		default:
			G_OBJECT_WARN_INVALID_PROPERTY_ID(inObject, inPropID, inSpec);
			break;
	}
}

/* Class initialization
 * Override functions in parent classes and define properties and signals
 */
static void cookie_permission_manager_class_init(CookiePermissionManagerClass *klass)
{
	GObjectClass		*gobjectClass=G_OBJECT_CLASS(klass);

	/* Override functions */
	gobjectClass->finalize=cookie_permission_manager_finalize;
	gobjectClass->set_property=cookie_permission_manager_set_property;
	gobjectClass->get_property=cookie_permission_manager_get_property;

	/* Set up private structure */
	g_type_class_add_private(klass, sizeof(CookiePermissionManagerPrivate));

	/* Define properties */
	CookiePermissionManagerProperties[PROP_EXTENSION]=
		g_param_spec_object("extension",
								_("Extension instance"),
								_("The Midori extension instance for this extension"),
								MIDORI_TYPE_EXTENSION,
								G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY);

	CookiePermissionManagerProperties[PROP_APPLICATION]=
		g_param_spec_object("application",
								_("Application instance"),
								_("The Midori application instance this extension belongs to"),
								MIDORI_TYPE_APP,
								G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY);

	g_object_class_install_properties(gobjectClass, PROP_LAST, CookiePermissionManagerProperties);
}

/* Object initialization
 * Create private structure and set up default values
 */
static void cookie_permission_manager_init(CookiePermissionManager *self)
{
	CookiePermissionManagerPrivate	*priv;

	priv=self->priv=COOKIE_PERMISSION_MANAGER_GET_PRIVATE(self);

	/* Set up default values */
	priv->database=NULL;

	/* Hijack session's cookie jar to handle cookies requests on our own in HTTP streams
	 * but remember old handlers to restore them on deactivation
	 */
	priv->session=webkit_get_default_session();
	priv->cookieJar=SOUP_COOKIE_JAR(soup_session_get_feature(priv->session, SOUP_TYPE_COOKIE_JAR));
	priv->featureIface=SOUP_SESSION_FEATURE_GET_CLASS(priv->cookieJar);
	g_object_set_data(G_OBJECT(priv->cookieJar), "cookie-permission-manager", self);

	priv->oldRequestQueued=priv->featureIface->request_queued;
	priv->oldRequestUnqueued=priv->featureIface->request_unqueued;

	priv->featureIface->request_queued=_cookie_permission_manager_request_queued;
	priv->featureIface->request_unqueued=_cookie_permission_manager_request_unqueued;

	/* Listen to changed cookies set or changed by other sources like javascript */
	priv->cookieJarChangedID=g_signal_connect_swapped(priv->cookieJar, "changed", G_CALLBACK(_cookie_permission_manager_on_cookie_changed), self);
}

/* Implementation: Public API */

/* Create new object */
CookiePermissionManager* cookie_permission_manager_new(MidoriExtension *inExtension, MidoriApp *inApp)
{
	return(g_object_new(TYPE_COOKIE_PERMISSION_MANAGER,
							"extension", inExtension,
							"application", inApp,
							NULL));
}
