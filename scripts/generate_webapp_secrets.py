#!/usr/bin/env python3
from __future__ import annotations

import base64
import os
import secrets


def main() -> None:
    app_secret = secrets.token_urlsafe(48)
    data_key = base64.urlsafe_b64encode(os.urandom(32)).decode("ascii")
    print(f"CAL_WEBAPP_SECRET={app_secret}")
    print(f"CAL_WEBAPP_DATA_KEY={data_key}")


if __name__ == "__main__":
    main()
