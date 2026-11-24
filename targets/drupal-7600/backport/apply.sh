#!/bin/sh
# Backport Drupal 8.5.1's fix for CVE-2018-7600 (SA-CORE-2018-002) onto the 8.5.0
# tree in the current directory: add RequestSanitizer and call it first thing in
# DrupalKernel::preHandle, as 8.5.1 does. Used only for the PATCHED=1 variant of
# the image, the negative control of the image tests; that variant is never pushed.
#
# Usage: apply.sh <directory holding RequestSanitizer.php>
set -eu
src=$1
kernel=core/lib/Drupal/Core/DrupalKernel.php
cp "$src/RequestSanitizer.php" core/lib/Drupal/Core/Security/RequestSanitizer.php

# the import, in order before Drupal\Core\Site\Settings
sed -i 's|^use Drupal\\Core\\Site\\Settings;$|use Drupal\\Core\\Security\\RequestSanitizer;\nuse Drupal\\Core\\Site\\Settings;|' "$kernel"
# the call, before anything else in preHandle
sed -i '/^  public function preHandle(Request \$request) {$/a\
    // Sanitize the request.\
    $request = RequestSanitizer::sanitize(\
      $request,\
      (array) Settings::get(RequestSanitizer::SANITIZE_WHITELIST, []),\
      (bool) Settings::get(RequestSanitizer::SANITIZE_LOG, FALSE)\
    );' "$kernel"

# each edit must have landed exactly once
[ "$(grep -c '^use Drupal\\Core\\Security\\RequestSanitizer;$' "$kernel")" = 1 ]
[ "$(grep -c 'RequestSanitizer::sanitize($' "$kernel")" = 1 ]
php -l "$kernel" >/dev/null
php -l core/lib/Drupal/Core/Security/RequestSanitizer.php >/dev/null
