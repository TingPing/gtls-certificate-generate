/* devs-tls-certificate.c
 *
 * Copyright 2018 Christian Hergert <chergert@redhat.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "devs-tls-certificate.h"

#include <errno.h>
#include <string.h>
#include <glib/gstdio.h>
#include <gnutls/x509.h>

#define DEFAULT_KEY_SIZE 4096

static void
_gnutls_datum_clear (gnutls_datum_t *datum)
{
  if (datum->data != NULL)
    gnutls_free (datum->data);
}

static void
_gnutls_crt_free (gnutls_x509_crt_t *cert)
{
  if (cert != NULL)
    gnutls_x509_crt_deinit (*cert);
}

static void
_gnutls_privkey_free (gnutls_x509_privkey_t *privkey)
{
  if (privkey != NULL)
    gnutls_x509_privkey_deinit (*privkey);
}

G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC(gnutls_datum_t, _gnutls_datum_clear)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(gnutls_x509_crt_t, _gnutls_crt_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(gnutls_x509_privkey_t, _gnutls_privkey_free)

typedef struct
{
  gchar *public_key_path;
  gchar *private_key_path;
  gchar *c;
  gchar *cn;
} GenerateData;

static void
generate_data_free (GenerateData *data)
{
  g_clear_pointer (&data->public_key_path, g_free);
  g_clear_pointer (&data->private_key_path, g_free);
  g_clear_pointer (&data->c, g_free);
  g_clear_pointer (&data->cn, g_free);
  g_slice_free (GenerateData, data);
}

static gboolean
make_directory_parent (const gchar  *path,
                       GError      **error)
{
  g_autofree gchar *dir = NULL;

  g_assert (path != NULL);
  g_assert (error != NULL);

  dir = g_path_get_dirname (path);

  if (g_mkdir_with_parents (dir, 0750) == -1)
    {
      g_set_error_literal (error,
                           G_IO_ERROR,
                           g_io_error_from_errno (errno),
                           g_strerror (errno));
      return FALSE;
    }

  return TRUE;
}

static void
devs_tls_certificate_generate_worker (GTask        *task,
                                      gpointer      source_object,
                                      gpointer      task_data,
                                      GCancellable *cancellable)
{
  GenerateData *data = task_data;
  g_autoptr(GTlsCertificate) certificate = NULL;
  g_autoptr(GError) error = NULL;
  g_autoptr(gnutls_x509_crt_t) certptr = NULL;
  g_autoptr(gnutls_x509_privkey_t) privkeyptr = NULL;
  g_auto(gnutls_datum_t) pubkey_data = { 0 };
  g_auto(gnutls_datum_t) privkey_data = { 0 };
  g_autofree char *dn = NULL;
  int gtlsret = 0;
  gnutls_x509_crt_t cert;
  gnutls_x509_privkey_t privkey;

  g_assert (G_IS_TASK (task));
  g_assert (source_object == NULL);
  g_assert (data != NULL);
  g_assert (data->public_key_path != NULL);
  g_assert (data->private_key_path != NULL);
  g_assert (data->c != NULL);
  g_assert (data->cn != NULL);

  if (!make_directory_parent (data->public_key_path, &error) ||
      !make_directory_parent (data->private_key_path, &error))
    {
      g_task_return_error (task, g_steal_pointer (&error));
      return;
    }

#define HANDLE_FAILURE(x) G_STMT_START {\
  gtlsret = x; \
  if (gtlsret != GNUTLS_E_SUCCESS) \
    goto failure; \
} G_STMT_END

  HANDLE_FAILURE(gnutls_x509_crt_init (&cert));
  certptr = &cert;
  HANDLE_FAILURE(gnutls_x509_crt_set_version (cert, 3));
  HANDLE_FAILURE(gnutls_x509_crt_set_serial (cert, "\x00", 1));
  HANDLE_FAILURE(gnutls_x509_crt_set_activation_time (cert, time (NULL)));
  dn = g_strdup_printf ("C=%s,CN=%s", data->c, data->cn);
  HANDLE_FAILURE(gnutls_x509_crt_set_dn (cert, dn, NULL));
  /* 5 years. We'll figure out key rotation in that time... */
  HANDLE_FAILURE(gnutls_x509_crt_set_expiration_time (cert, time (NULL) + (60*60*24*5*365)));

  HANDLE_FAILURE(gnutls_x509_privkey_init (&privkey));
  privkeyptr = &privkey;
  HANDLE_FAILURE(gnutls_x509_privkey_generate (privkey, GNUTLS_PK_RSA, DEFAULT_KEY_SIZE, 0));
  HANDLE_FAILURE(gnutls_x509_crt_set_key (cert, privkey));

  HANDLE_FAILURE(gnutls_x509_crt_sign (cert, cert, privkey));

  HANDLE_FAILURE(gnutls_x509_crt_export2 (cert, GNUTLS_X509_FMT_PEM, &pubkey_data));
  if (!g_file_set_contents(data->public_key_path, (char*)pubkey_data.data, pubkey_data.size, &error))
    goto failure;

  HANDLE_FAILURE(gnutls_x509_privkey_export2 (privkey, GNUTLS_X509_FMT_PEM, &privkey_data));
  if (!g_file_set_contents(data->private_key_path, (char*)privkey_data.data, privkey_data.size, &error))
    goto failure;

  certificate = g_tls_certificate_new_from_files (data->public_key_path,
                                                  data->private_key_path,
                                                  &error);

  if (certificate != NULL)
    {
      g_task_return_pointer (task, g_steal_pointer (&certificate), g_object_unref);
      return;
    }

failure:
  if (error != NULL)
    g_task_return_error (task, g_steal_pointer (&error));
  else if (gtlsret != 0)
    {
      g_autofree char *errstring = g_strdup_printf ("GnuTLS Error: %s", gnutls_strerror (gtlsret));
      g_task_return_new_error (task,
                               G_IO_ERROR,
                               G_IO_ERROR_FAILED,
                               errstring);
    }
  else
    g_task_return_new_error (task,
                             G_IO_ERROR,
                             G_IO_ERROR_FAILED,
                             "Failed to generate TLS certificate pair");
}

void
devs_tls_certificate_new_generate_async (const gchar         *public_key_path,
                                         const gchar         *private_key_path,
                                         const gchar         *c,
                                         const gchar         *cn,
                                         GCancellable        *cancellable,
                                         GAsyncReadyCallback  callback,
                                         gpointer             user_data)
{
  g_autoptr(GTask) task = NULL;
  GenerateData *data;

  g_return_if_fail (public_key_path != NULL);
  g_return_if_fail (private_key_path != NULL);
  g_return_if_fail (c != NULL);
  g_return_if_fail (cn != NULL);
  g_return_if_fail (!cancellable || G_IS_CANCELLABLE (cancellable));

  task = g_task_new (NULL, cancellable, callback, user_data);
  g_task_set_source_tag (task, devs_tls_certificate_new_generate_async);

  data = g_slice_new0 (GenerateData);
  data->public_key_path = g_strdup (public_key_path);
  data->private_key_path = g_strdup (private_key_path);
  data->c = g_strdup (c);
  data->cn = g_strdup (cn);
  g_task_set_task_data (task, data, (GDestroyNotify)generate_data_free);

  g_task_run_in_thread (task, devs_tls_certificate_generate_worker);
}

GTlsCertificate *
devs_tls_certificate_new_generate_finish (GAsyncResult  *result,
                                          GError       **error)
{
  g_return_val_if_fail (G_IS_TASK (result), NULL);

  return g_task_propagate_pointer (G_TASK (result), error);
}

GTlsCertificate *
devs_tls_certificate_new_generate (const gchar   *public_key_path,
                                   const gchar   *private_key_path,
                                   const gchar   *c,
                                   const gchar   *cn,
                                   GCancellable  *cancellable,
                                   GError       **error)
{
  g_autoptr(GTask) task = NULL;
  GenerateData *data;

  g_return_val_if_fail (public_key_path != NULL, NULL);
  g_return_val_if_fail (private_key_path != NULL, NULL);
  g_return_val_if_fail (c != NULL, NULL);
  g_return_val_if_fail (cn != NULL, NULL);
  g_return_val_if_fail (!cancellable || G_IS_CANCELLABLE (cancellable), NULL);

  task = g_task_new (NULL, cancellable, NULL, NULL);
  g_task_set_source_tag (task, devs_tls_certificate_new_generate);

  data = g_slice_new0 (GenerateData);
  data->public_key_path = g_strdup (public_key_path);
  data->private_key_path = g_strdup (private_key_path);
  data->c = g_strdup (c);
  data->cn = g_strdup (cn);
  g_task_set_task_data (task, data, (GDestroyNotify)generate_data_free);

  devs_tls_certificate_generate_worker (task, NULL, data, cancellable);

  return g_task_propagate_pointer (task, error);
}
