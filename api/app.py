from flask import Flask, request, jsonify
import whois

app = Flask(__name__)

@app.route('/whois', methods=['GET'])
def get_whois_data():
    # Get the domain name from the request
    domain = request.args.get('aman')
    
    if not domain:
        return jsonify({"error": "Domain name is required"}), 400

    try:
        # Fetch WHOIS data
        domain_info = whois.whois(domain)
        
        # Prepare the response with relevant fields
        response_data = {
            "domain_name": domain_info.domain_name,
            "registrar": domain_info.registrar,
            "creation_date": domain_info.creation_date,
            "expiration_date": domain_info.expiration_date,
            "updated_date": domain_info.updated_date,
            "name_servers": domain_info.name_servers,
            "status": domain_info.status,
            "emails": domain_info.emails,
        }
        return jsonify(response_data), 200
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':

    app.run(debug=True,port=5001)
