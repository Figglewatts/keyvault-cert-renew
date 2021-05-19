# keyvault-cert-renew
Renew Let's Encrypt certificates in an Azure Key Vault automatically with an Azure function.

## Developer guide

### Prerequisites
- Python 3.8
- Poetry
- Serverless Framework
- Azure CLI

### Quick start
1. Clone the repo.
2. Run `poetry install`.
3. Run `npm install`.
4. Ensure you are logged in with Azure CLI (`az login`).
5. You're good to go. You can test the function locally 
   with `poetry run sls offline`.