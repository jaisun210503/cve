The script works by first fetching CVE data from the NVD API in batches, pulling 2000 CVEs at a time using the fetch_cves() function. The fetched data is then stored in an SQLite3 database, which is a lightweight, file-based database suitable for this project since the CVE data is public and doesn’t require complex security measures. The create_database() function makes sure the database and necessary table are set up if they don't already exist. Once the database is ready, the populate_database() function processes each CVE, extracting details like CVE ID, description, and CVSS scores. For each CVE, the script inserts or updates the record in the database using the INSERT OR REPLACE query. The database is committed every 100 CVEs to avoid data loss and improve performance. The script loops through the data, fetching and processing CVEs until a specified limit is reached or no more data is available. A 6-second delay is added between requests to prevent overwhelming the NVD API. Using SQLite3 and Streamlit ensures that the system is efficient and lightweight, reducing resource usage, as the data is public and doesn’t require advanced infrastructure or security measures. 
The data can then be used in the Streamlit app for further analysis or visualization.
