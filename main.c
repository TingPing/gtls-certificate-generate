/* main.c
 *
 * Copyright 2018 Patrick Griffis <tingping@tingping.se>
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

int
main(int argc, char **argv)
{
  g_autoptr(GTlsCertificate) cert;
  g_autoptr(GError) err = NULL;

  cert = devs_tls_certificate_new_generate ("pub.pem", "priv.pem", "US", "Foo", NULL, &err);
  if (err)
    g_error ("%s", err->message);

  return 0;
}