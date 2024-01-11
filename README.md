<!--
SPDX-FileCopyrightText: Copyright 2022 EDF (Électricité de France S.A.)
SPDX-License-Identifier: BSD-3-Clause
-->
CoAP/ACE-OAuth PoC: Web application
===================================

This repository contains the web app part of the CoAP/ACE-OAuth proof-of-concept implementation.
The firmware is written in Rust,
and designed to run on browsers that implement the [Web Bluetooth API].

[Web Bluetooth API]: https://webbluetoothcg.github.io/web-bluetooth/

**For an overview of what this does
and how it is used in practice, please see
[the corrresponding firmware's README file],
which explains the whole setup.**

Documentation on the implementation is [available through GitLab pages].

[the corrresponding firmware's README file]: https://gitlab.com/oscore/coap-ace-poc-firmware/-/blob/main/README.md
[available through GitLab pages]: https://oscore.gitlab.io/coap-ace-poc-webapp/doc/coap_ace_poc_webapp/

Typical issues
--------------

* "I changed something in the code, and now things are stuck at WASM load time with errors such as `Uncaught TypeError: Failed to resolve module specifier "env".`"

  This is the Rust-WASM-browser way of telling you that there are missing symbols
  (something the linker and wasm-bindgen can't tell you, for you might be providing them inside JavaScript).

  You can find out which they are by applying `wasm-dis` to the `public/*.wasm`, and looking for mentions of "env" -- these will point you to the missing symbol.

License
-------

This project and all files contained in it is published under the
BSD-3-Clause license as defined in [`LICENSES/BSD-3-Clause.txt`](LICENSES/BSD-3-Clause.txt).

Copyright: 2022 EDF (Électricité de France S.A.)

Author: Christian Amsüss

Note that additional terms may apply to the built output.
