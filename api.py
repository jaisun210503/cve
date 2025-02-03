from flask import Flask, jsonify, render_template, request
from flask_cors import CORS
import sqlite3

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})

def get_db_connection():
    conn = sqlite3.connect('cve_database.db')
    conn.row_factory = sqlite3.Row
    return conn


@app.route('/api/cves', methods=['GET'])
def get_cves():
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 10))
    offset = (page - 1) * per_page
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    total_count = cursor.execute('SELECT COUNT(*) FROM cves').fetchone()[0]
    
    cves = cursor.execute('''
        SELECT * FROM cves 
        ORDER BY last_modified DESC
        LIMIT ? OFFSET ?
    ''', (per_page, offset)).fetchall()
    
    conn.close()
    
    return jsonify({
        'cves': [dict(cve) for cve in cves],
        'total': total_count,
        'page': page,
        'per_page': per_page,
        'total_pages': (total_count + per_page - 1) // per_page
    })


@app.route('/api/cves/<cve_id>', methods=['GET'])
def get_cve(cve_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cve = cursor.execute('SELECT * FROM cves WHERE cve_id = ?', (cve_id,)).fetchone()
    conn.close()
    
    if cve is None:
        return jsonify({'error': 'CVE not found'}), 404
    return jsonify(dict(cve))


@app.route('/cves/<cve_id>', methods=['GET'])
def cve_detail_page(cve_id):
    return render_template('cve_detail.html', cve_id=cve_id)

if __name__ == '__main__':
    app.run(debug=True)
