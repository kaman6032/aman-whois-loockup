# from flask import Flask, jsonify, request
# import whois

# app = Flask(__name__)

# @app.route('/whois/<domain>', methods=['GET'])
# def whois_lookup(domain):
#     try:
#         domain_info = whois.whois(domain)
#         return jsonify(domain_info)
#     except Exception as e:
#         return jsonify({'error': str(e)}), 500

# if __name__ == '__main__':
#     app.run(debug=True, host='0.0.0.0', port=5000)
from flask import Flask, jsonify, request
import whois
import logging

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def remove_null_fields(data):
    """Recursively remove null and empty fields from a dictionary."""
    if isinstance(data, dict):
        return {k: remove_null_fields(v) for k, v in data.items() if v not in [None, "", []]}
    elif isinstance(data, list):
        return [remove_null_fields(v) for v in data if v not in [None, "", []]]
    else:
        return data

@app.route('/whois/<domain>', methods=['GET'])
def whois_lookup(domain):
    logger.info(f"Received WHOIS request for domain: {domain}")
    try:
        domain_info = whois.whois(domain)
        domain_info_dict = domain_info if isinstance(domain_info, dict) else domain_info.__dict__

        # Prepare the response in the desired format
        response = {
            "WhoisRecord": {
                "createdDate": domain_info_dict.get('creation_date'),
                "updatedDate": domain_info_dict.get('updated_date'),
                "expiresDate": domain_info_dict.get('expiration_date'),
                "registrant": {
                    "organization": domain_info_dict.get('org'),
                    "state": domain_info_dict.get('state'),
                    "country": domain_info_dict.get('country'),
                    "countryCode": domain_info_dict.get('country_code'),
                    "rawText": domain_info_dict.get('org')
                },
                "administrativeContact": {
                    "organization": domain_info_dict.get('org'),
                    "state": domain_info_dict.get('state'),
                    "country": domain_info_dict.get('country'),
                    "countryCode": domain_info_dict.get('country_code'),
                    "rawText": domain_info_dict.get('org')
                },
                "technicalContact": {
                    "organization": domain_info_dict.get('org'),
                    "state": domain_info_dict.get('state'),
                    "country": domain_info_dict.get('country'),
                    "countryCode": domain_info_dict.get('country_code'),
                    "rawText": domain_info_dict.get('org')
                },
                "domainName": domain_info_dict.get('domain_name'),
                "nameServers": {
                    "rawText": " ".join(domain_info_dict.get('name_servers', [])),
                    "hostNames": domain_info_dict.get('name_servers', []),
                    "ips": []
                },
                "status": domain_info_dict.get('status'),
                "rawText": domain_info_dict.get('raw'),
                "audit": {
                    "createdDate": None,
                    "updatedDate": None
                },
                "customField1Name": "RegistrarContactEmail",
                "customField1Value": domain_info_dict.get('emails'),
                "registrarName": domain_info_dict.get('registrar'),
                "registrarIANAID": None,
                "createdDateNormalized": domain_info_dict.get('creation_date'),
                "updatedDateNormalized": domain_info_dict.get('updated_date'),
                "expiresDateNormalized": domain_info_dict.get('expiration_date'),
                "customField2Name": "RegistrarContactPhone",
                "customField3Name": "RegistrarURL",
                "customField2Value": None,
                "customField3Value": None,
                "registryData": {
                    "createdDate": domain_info_dict.get('creation_date'),
                    "updatedDate": domain_info_dict.get('updated_date'),
                    "expiresDate": domain_info_dict.get('expiration_date'),
                    "domainName": domain_info_dict.get('domain_name'),
                    "nameServers": {
                        "rawText": " ".join(domain_info_dict.get('name_servers', [])),
                        "hostNames": domain_info_dict.get('name_servers', []),
                        "ips": []
                    },
                    "status": domain_info_dict.get('status'),
                    "rawText": domain_info_dict.get('raw'),
                    "audit": {
                        "createdDate": None,
                        "updatedDate": None
                    },
                    "customField1Name": "RegistrarContactEmail",
                    "customField1Value": domain_info_dict.get('emails'),
                    "registrarName": domain_info_dict.get('registrar'),
                    "registrarIANAID": None,
                    "createdDateNormalized": domain_info_dict.get('creation_date'),
                    "updatedDateNormalized": domain_info_dict.get('updated_date'),
                    "expiresDateNormalized": domain_info_dict.get('expiration_date'),
                    "customField2Name": "RegistrarContactPhone",
                    "customField3Name": "RegistrarURL",
                    "customField2Value": None,
                    "customField3Value": None,
                    "whoisServer": domain_info_dict.get('whois_server')
                },
                "domainAvailability": "UNAVAILABLE",
                "contactEmail": domain_info_dict.get('emails'),
                "domainNameExt": domain_info_dict.get('tld'),
                "estimatedDomainAge": None,
                "ips": []
            }
        }

        # Remove null and empty fields from the response
        response = remove_null_fields(response)

        logger.info(f"WHOIS lookup successful for domain: {domain}")
        return jsonify(response)
    except Exception as e:
        logger.error(f"Error during WHOIS lookup for domain: {domain} - {e}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
