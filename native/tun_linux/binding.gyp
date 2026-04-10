{
  "targets": [
    {
      "target_name": "tun_linux",
      "conditions": [
        [
          "OS=='linux'",
          {
            "sources": ["tun_linux.cc"],
            "defines": ["NAPI_VERSION=8"],
            "cflags_cc": ["-fPIC", "-Wall", "-Wextra", "-O2"]
          },
          {
            "sources": ["stub.c"],
            "defines": ["NAPI_VERSION=8"]
          }
        ]
      ]
    }
  ]
}
