# PikaMLRelay
This application is quickly and dirty written proxy server for the only use of my Master's project.
Its only goal is to modify requests sent from backend which interacts with user to Ollama server - the task mostly consists of adding a sytsem prompt for specific models, verifies some abilities of models such as tool support or loads configured tools and downloads applicable scripts from my cloud storage.

Application is written using C11 and [facil.io](https://facil.io) high-performance webframework.
