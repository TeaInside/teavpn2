<?php

gen_linux(
  (function () {
    $ret = [
      __DIR__."/src/sources/teavpn2/server/vpn/iface/linux.h",
      __DIR__."/src/sources/teavpn2/server/vpn/tcp/linux.h",
      __DIR__."/src/sources/teavpn2/server/vpn/udp/linux.h",
    ];
    
    $ret = array_merge(
      $ret,
      glob(__DIR__."/src/sources/teavpn2/server/vpn/tcp/linux/*.h")
    );

    return $ret;
  })(),
  __DIR__."/src/include/teavpn2/server/vpn/linux_inline_contracts.h"
);

/**
 * @param string $file
 * @return string
 */
function gen_inline_abstractions(string $file): string
{
  $content = file_get_contents($file);

  $retval = "";
  if (preg_match_all("/(inline static .+?\))[\\s\\n]+?\{/s", $content, $m)) {
    foreach ($m[1] as $k => $v) {
      $retval .= $v.";\n\n";
    }
  }

  return $retval;
}

/**
 * @param array  $files
 * @param string $targetFile
 * @return void
 */
function gen_linux(array $files, string $targetFile): void
{
  $ctx = <<<FILE

#ifndef TEAVPN2__SERVER__VPN__LINUX_INLINE_CONTRACTS_H
#define TEAVPN2__SERVER__VPN__LINUX_INLINE_CONTRACTS_H


FILE;

  foreach ($files as $file) {
    $ctx .= gen_inline_abstractions($file);  
  }

  $ctx .= <<<FILE
#endif /* #ifndef TEAVPN2__SERVER__VPN__LINUX_INLINE_CONTRACTS_H */

FILE;
  file_put_contents($targetFile, $ctx);
}
