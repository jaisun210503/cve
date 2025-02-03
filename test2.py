import streamlit as st
import requests
import pandas as pd

API_URL = 'http://localhost:5000/api/cves'

def fetch_cves(page=1, per_page=10):
    params = {'page': page, 'per_page': per_page}
    response = requests.get(API_URL, params=params)
    
    if response.status_code == 200:
        data = response.json()
        return pd.DataFrame(data['cves'])
    else:
        return pd.DataFrame()

def fetch_cve_details(cve_id):
    response = requests.get(f"{API_URL}/{cve_id}")
    if response.status_code == 200:
        return response.json()
    else:
        return None

def main():
    st.title("CVE List")

    page = st.sidebar.number_input("Select Page", min_value=1, value=1, step=1)
    per_page = st.sidebar.selectbox("Results Per Page", [10, 50, 100], index=0)

    cves_df = fetch_cves(page=page, per_page=per_page)

    if cves_df.empty:
        st.write("No CVEs found or unable to fetch data.")
        return

    total_cves = cves_df.shape[0]
    total_pages = (total_cves + per_page - 1) // per_page
    st.write(f"Total CVEs: {total_cves}")
    st.write(f"Page {page} of {total_pages}")
    
    cves_df = cves_df[['cve_id', 'published', 'last_modified', 'status']]
    cves_df['Identifier'] = 'cve@mitre.org'
    cves_df.rename(columns={
        'cve_id': 'CVE ID',
        'published': 'Published',
        'last_modified': 'Last Modified',
        'status': 'Status'
    }, inplace=True)

    selected_cve = st.selectbox("Select a CVE to view details", cves_df['CVE ID'])

    if selected_cve:
        cve_details = fetch_cve_details(selected_cve)
        
        if cve_details:
            st.subheader(f"Details for CVE {selected_cve}")
            st.write(f"**CVE ID:** {cve_details.get('cve_id', 'N/A')}")
            st.write(f"**Description:** {cve_details.get('description', 'N/A')}")
            st.write(f"**CVSS v2 Score:** {cve_details.get('cvss_v2_score', 'N/A')}")
            st.write(f"**CVSS v3 Score:** {cve_details.get('cvss_v3_score', 'N/A')}")
            st.write(f"**Access Complexity:** {cve_details.get('access_complexity', 'N/A')}")
            st.write(f"**Severity:** {cve_details.get('severity', 'N/A')}")
            st.write(f"**Vector String:** {cve_details.get('vector_string', 'N/A')}")
            st.write(f"**Exploitability Score:** {cve_details.get('exploitability_score', 'N/A')}")
        else:
            st.write("Details not found.")
    
    st.write("### CVEs List")
    st.dataframe(cves_df)

    col1, col2 = st.columns([1, 1])
    
    with col1:
        if page > 1:
            prev_page = page - 1
            st.button(f"Previous (Page {prev_page})", on_click=main, args=(prev_page, per_page))
    
    with col2:
        if page < total_pages:
            next_page = page + 1
            st.button(f"Next (Page {next_page})", on_click=main, args=(next_page, per_page))

if __name__ == "__main__":
    main()
