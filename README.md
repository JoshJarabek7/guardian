# Guardian (WORK IN PROGRESS)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Guardian is a Python package that provides easy-to-use decorators for FastAPI routes to enhance security and functionality. It aims to offer modular and customizable solutions for common security features, allowing developers to choose the batteries they need without the bloat.

## Features

### Virus Scanning for FileUpload API Endpoints
- Simple decorator to scan file uploads using ClamAV
- Extensive customization options to add desired flags
- Set default settings on startup and tweak them for specific endpoints
- Automated checks for virus signature updates using FreshClam abstraction
- Fully asynchronous to seamlessly integrate with FastAPI

### HTML & String Sanitizer
- Simple decorator to automatically sanitize inputs and prevent HTML & SQL injection
- Integration with Pydantic for input validation

### Session-based and Token-based Authentication and Authorization
- Integration with your database and cache
- Set rules ahead of time to automate authentication and authorization flow, reducing boilerplate code for each endpoint
- Compatibility with both stateful and stateless authentication flows
- Automatic attachment and verification of CSRF tokens on request and response

## Planned Features

### Optional Pip Flags and Future Frameworks
- Lightweight installation with only the minimum required packages
- Support for Flask and other frameworks
- Standalone package for vanilla Python to scan files not necessarily from a client

## Installation
TODO - Not on PyPi yet, we have a long way to go. Placeholder.

## Usage

```python
from fastapi import FastAPI, File, UploadFile
from guardian import clamav_scanner

app = FastAPI()

@app.post("/upload")
@clamav_scanner()
async def upload_file(file: UploadFile = File(...)):
    # Process the clean file
    pass
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