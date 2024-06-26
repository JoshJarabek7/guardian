# Hiss 🐍 (WORK IN PROGRESS)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Hiss 🐍 is a Python package that provides easy-to-use decorators and middleware for FastAPI/Starlette routes to enhance security and functionality. It aims to offer modular and customizable solutions for common security features, allowing developers to choose the batteries they need without the bloat.

# Roadmap

## Virus Scanning (STATUS: IN-PROGRESS)

- Drop-in decorator for routes (COMPLETED)
- Drop-in middleware for FastAPI & Starlette (COMPLETED)
- Automated checks for virus signature updates using FreshClam abstraction (COMPLETED)
- Extensive customization options to add desired flags (COMPLETED)
- Set default settings on startup and tweak them for specific endpoints (COMPLETED)
- Adapters for use with different ClamAV versions (IN-PROGRESS)
- Option for compilation of ClamAV C library to bundle installation with pip package (IN-PROGRESS)
- C-Bindings for libclamav (IN-PROGRESS - need to investigate FOSS licensing for it)
- Deploy to PyPI (IN-PROGRESS)

## Sanitizer (STATUS: NOT STARTED)
- Simple decorator to automatically sanitize inputs and prevent HTML & SQL injection (NOT STARTED)
- Simple middleware to automatically sanitize inputs and prevent HTML & SQL injection (NOT STARTED)

## Session-based and Token-based Auth
- Integration with your database and cache (NOT STARTED)
- Set rules ahead of time to automate authentication and authorization flow, reducing boilerplate code for each endpoint (NOT STARTED)
- Compatibility with both stateful and stateless authentication flows (NOT STARTED)
- Automatic attachment and verification of CSRF tokens on request and response (NOT STARTED)

## Extensive Documentation
- Virus Scanning (NOT STARTED)
- Sanitizer (NOT STARTED)
- Auth (NOT STARTED)
- There will be a lot of breaking changes, so I will not start on documentation until things become a little more stable.

## Templating Repo
- Create Dockerfile templates and scripting for serverless scanning to keep malicious files separate from web servers (NOT STARTED)
- Easy Forwarding Scripts to forward files or alerts to specific endpoints (NOT STARTED)
- Integrate AMQP (NOT STARTED)

## Other
- 100% Coverage Testing for unit and integration (IN-PROGRESS)
- WebAssembly Runtime for browser? (TBD / NOT-STARTED)
- Sandboxing (IN-PROGRESS)
- Completely in-memory (INVESTIGATING)

Feel free to discuss or suggest ideas and features in the Discussions tab!

## Installation
TODO - Not on PyPi yet, we have a long way to go. Placeholder.

## Usage

```python
from fastapi import FastAPI, File, UploadFile
from hiss import scan_upload
from hiss.fastapi.middleware import FileUploadScanMiddleware

app = FastAPI()

# --- OPTION 1: Middleware-based option (automatic) ---
app.add_middleware(FileUploadScanMiddleware) # That's it!

@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    # Process the clean file (middleware cleaned it already)
    pass
# --- END OPTION 1 ---

# --- OPTION 2: Decorator-based option ---
@app.post("/upload")
@scan_upload() # That's it!
async def upload_file(file: UploadFile = File(...)):
    # Process the clean file (decorator cleaned it already)
    pass
# --- END OPTION 2 ---
```

For more detailed usage instructions and examples, please refer to the [documentation (TODO)](google.com).

## Contributing

TODO - Contributions are welcome! Please read the [contribution guidelines](CONTRIBUTING.md) for more information.

## License

This project is licensed under the terms of the [MIT License](LICENSE).

## Acknowledgements

- [FastAPI](https://fastapi.tiangolo.com/)
- [ClamAV](https://www.clamav.net/)
- [Pydantic](https://pydantic-docs.helpmanual.io/)

## Contact

For any questions or inquiries, please contact [jarabekjosh@icloud.com](mailto:jarabekjosh@icloud.com).