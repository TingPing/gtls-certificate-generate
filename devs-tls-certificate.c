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
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#define DEFAULT_KEY_SIZE 4096

G_DEFINE_AUTOPTR_CLEANUP_FUNC (BIGNUM, BN_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC (EVP_PKEY, EVP_PKEY_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC (X509, X509_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC (RSA, RSA_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC (BIO, BIO_free)

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
  g_autoptr(EVP_PKEY) pk  = NULL;
  g_autoptr(BIGNUM) bne = NULL;
  g_autoptr(X509) x = NULL;
  g_autoptr(RSA) rsa = NULL;
  g_autoptr(BIO) pubkey = NULL;
  g_autoptr(BIO) privkey = NULL;
  X509_NAME *name;

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

  pk = EVP_PKEY_new ();
  if (pk == NULL)
    goto failure;

  x = X509_new ();
  if (x == NULL)
    goto failure;

  bne = BN_new ();
  if (bne == NULL || !BN_set_word (bne, RSA_F4))
    goto failure;

  rsa = RSA_new ();
  if (rsa == NULL || !RSA_generate_key_ex (rsa, DEFAULT_KEY_SIZE, bne, NULL))
    goto failure;

  if (!EVP_PKEY_assign_RSA (pk, g_steal_pointer (&rsa)))
    goto failure;

  X509_set_version (x, 2);
  ASN1_INTEGER_set (X509_get_serialNumber (x), 0);
  X509_gmtime_adj (X509_get_notBefore (x), 0);
  /* 5 years. We'll figure out key rotation in that time... */
  X509_gmtime_adj (X509_get_notAfter (x), (long)60*60*24*5*365);
  X509_set_pubkey (x, pk);

  name = X509_get_subject_name (x);

  if (!X509_NAME_add_entry_by_txt (name, "C",
                                   MBSTRING_ASC, (guchar *)data->c, -1, -1, 0))
    goto failure;

  if (!X509_NAME_add_entry_by_txt (name, "CN",
                                   MBSTRING_ASC, (guchar *)data->cn, -1, -1, 0))
    goto failure;

  if (!X509_set_issuer_name (x, name))
    goto failure;

  if (!X509_sign (x, pk, EVP_md5 ()))
    goto failure;

  pubkey = BIO_new_file (data->public_key_path, "w+");
  if (pubkey == NULL || !PEM_write_bio_X509 (pubkey, x))
    goto failure;

  privkey = BIO_new_file (data->private_key_path, "w+");
  if (privkey == NULL || !PEM_write_bio_PrivateKey (privkey, pk, NULL, NULL, 0, NULL, NULL))
    goto failure;

  BIO_flush (pubkey);
  BIO_flush (privkey);

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
  else
    g_task_return_new_error (task,
                             G_IO_ERROR,
                             G_IO_ERROR_FAILED,
                             "Failed to generate TLS certificate pair");
}

void
devs_tls_certificate_new_generate_async (GFile               *public_key_file,
                                         GFile               *private_key_file,
                                         const gchar         *c,
                                         const gchar         *cn,
                                         GCancellable        *cancellable,
                                         GAsyncReadyCallback  callback,
                                         gpointer             user_data)
{
  g_autoptr(GTask) task = NULL;
  GenerateData *data;

  g_return_if_fail (G_IS_FILE (public_key_file));
  g_return_if_fail (G_IS_FILE (private_key_file));
  g_return_if_fail (c != NULL);
  g_return_if_fail (cn != NULL);
  g_return_if_fail (!cancellable || G_IS_CANCELLABLE (cancellable));

  task = g_task_new (NULL, cancellable, callback, user_data);
  g_task_set_source_tag (task, devs_tls_certificate_new_generate_async);

  if (g_file_equal (public_key_file, private_key_file))
    {
      g_task_return_new_error (task,
                               G_IO_ERROR,
                               G_IO_ERROR_NOT_REGULAR_FILE,
                               "Public and private key files may not be the same");
      return;
    }

  if (!g_file_is_native (public_key_file) ||
      !g_file_is_native (private_key_file))
    {
      g_task_return_new_error (task,
                               G_IO_ERROR,
                               G_IO_ERROR_NOT_REGULAR_FILE,
                               "Destination files are non-native and cannot be used");
      return;
    }

  data = g_slice_new0 (GenerateData);
  data->public_key_path = g_file_get_path (public_key_file);
  data->private_key_path = g_file_get_path (private_key_file);
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
