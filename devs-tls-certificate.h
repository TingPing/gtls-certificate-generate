/* devs-tls-certificate.h
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

#pragma once

#include <gio/gio.h>

G_BEGIN_DECLS

GTlsCertificate *devs_tls_certificate_new_generate        (GFile                *public_key_file,
                                                           GFile                *private_key_file,
                                                           const gchar          *c,
                                                           const gchar          *cn,
                                                           GCancellable         *cancellable,
                                                           GError              **error);
void             devs_tls_certificate_new_generate_async  (GFile                *public_key_file,
                                                           GFile                *private_key_file,
                                                           const gchar          *c,
                                                           const gchar          *cn,
                                                           GCancellable         *cancellable,
                                                           GAsyncReadyCallback   callback,
                                                           gpointer              user_data);
GTlsCertificate *devs_tls_certificate_new_generate_finish (GAsyncResult         *result,
                                                           GError              **error);

G_END_DECLS
