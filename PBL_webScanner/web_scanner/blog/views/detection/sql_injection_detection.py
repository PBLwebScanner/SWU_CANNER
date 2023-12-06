import requests
from urllib.parse import urljoin, urlencode, urlparse, parse_qs, urlsplit, urlunsplit
from bs4 import BeautifulSoup
import re
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

DBMS_ERROR_PATTERNS = {
    "MySQL": [
        re.compile(r"SQL syntax.*?MySQL"),
        re.compile(r"Warning.*?\Wmysqli?_"),
        re.compile(r"MySQLSyntaxErrorException"),
        re.compile(r"valid MySQL result"),
        re.compile(r"check the manual that (corresponds to|fits) your MySQL server version"),
        re.compile(r"Unknown column '[^ ]+' in 'field list'"),
        re.compile(r"MySqlClient\."),
        re.compile(r"com\.mysql\.jdbc"),
        re.compile(r"Zend_Db_(Adapter|Statement)_Mysqli_Exception"),
        re.compile(r"Pdo[./_\\]Mysql"),
        re.compile(r"MySqlException"),
        re.compile(r"SQLSTATE\[\d+\]: Syntax error or access violation")
    ],
    "MariaDB": [
        re.compile(r"check the manual that (corresponds to|fits) your MariaDB server version"),

    ],
    "Drizzle": [
        re.compile(r"check the manual that (corresponds to|fits) your Drizzle server version")
    ],
    "MemSQL": [
        re.compile(r"MemSQL does not support this type of query"),
        re.compile(r"is not supported by MemSQL"),
        re.compile(r"unsupported nested scalar subselect")
    ],
    "PostgreSQL": [
        re.compile(r"PostgreSQL.*?ERROR"),
        re.compile(r"Warning.*?\Wpg_"),
        re.compile(r"valid PostgreSQL result"),
        re.compile(r"Npgsql\."),
        re.compile(r"PG::SyntaxError:"),
        re.compile(r"org\.postgresql\.util\.PSQLException"),
        re.compile(r"ERROR:\s\ssyntax error at or near"),
        re.compile(r"ERROR: parser: parse error at or near"),
        re.compile(r"PostgreSQL query failed"),
        re.compile(r"org\.postgresql\.jdbc"),
        re.compile(r"Pdo[./_\\]Pgsql"),
        re.compile(r"PSQLException"),
    ],
    "Microsoft SQL Server": [
        re.compile(r"Driver.*? SQL[\-\_\ ]*Server"),
        re.compile(r"OLE DB.*? SQL Server"),
        re.compile(r"\bSQL Server[^&lt;&quot;]+Driver"),
        re.compile(r"Warning.*?\W(mssql|sqlsrv)_"),
        re.compile(r"\bSQL Server[^&lt;&quot;]+[0-9a-fA-F]{8}"),
        re.compile(r"System\.Data\.SqlClient\.SqlException"),
        re.compile(r"(?s)Exception.*?\bRoadhouse\.Cms\."),
        re.compile(r"Microsoft SQL Native Client error '[0-9a-fA-F]{8}"),
        re.compile(r"\[SQL Server\]"),
        re.compile(r"ODBC SQL Server Driver"),
        re.compile(r"ODBC Driver \d+ for SQL Server"),
        re.compile(r"SQLServer JDBC Driver"),
        re.compile(r"com\.jnetdirect\.jsql"),
        re.compile(r"macromedia\.jdbc\.sqlserver"),
        re.compile(r"Zend_Db_(Adapter|Statement)_Sqlsrv_Exception"),
        re.compile(r"com\.microsoft\.sqlserver\.jdbc"),
        re.compile(r"Pdo[./_\\](Mssql|SqlSrv)"),
        re.compile(r"SQL(Srv|Server)Exception"),
    ],
    "Microsoft Access": [
        re.compile(r"Microsoft Access (\d+ )?Driver"),
        re.compile(r"JET Database Engine"),
        re.compile(r"Access Database Engine"),
        re.compile(r"ODBC Microsoft Access"),
        re.compile(r"Syntax error \(missing operator\) in query expression"),
    ],
    "Oracle": [
        re.compile(r"\bORA-\d{5}"),
        re.compile(r"Oracle error"),
        re.compile(r"Oracle.*?Driver"),
        re.compile(r"Warning.*?\W(oci|ora)_"),
        re.compile(r"quoted string not properly terminated"),
        re.compile(r"SQL command not properly ended"),
        re.compile(r"macromedia\.jdbc\.oracle"),
        re.compile(r"oracle\.jdbc"),
        re.compile(r"Zend_Db_(Adapter|Statement)_Oracle_Exception"),
        re.compile(r"Pdo[./_\\](Oracle|OCI)"),
        re.compile(r"OracleException"),
    ],
    "IBM DB2": [
        re.compile(r"CLI Driver.*?DB2"),
        re.compile(r"DB2 SQL error"),
        re.compile(r"\bdb2_\w+\("),
        re.compile(r"SQLCODE[=:\d, -]+SQLSTATE"),
        re.compile(r"com\.ibm\.db2\.jcc"),
        re.compile(r"Zend_Db_(Adapter|Statement)_Db2_Exception"),
        re.compile(r"Pdo[./_\\]Ibm"),
        re.compile(r"DB2Exception"),
        re.compile(r"ibm_db_dbi\.ProgrammingError"),
    ],
    "Informix": [
        re.compile(r"Warning.*?\Wifx_"),
        re.compile(r"Exception.*?Informix"),
        re.compile(r"Informix ODBC Driver"),
        re.compile(r"ODBC Informix driver"),
        re.compile(r"com\.informix\.jdbc"),
        re.compile(r"weblogic\.jdbc\.informix"),
        re.compile(r"Pdo[./_\\]Informix"),
        re.compile(r"IfxException"),
    ],
    "Firebird": [
        re.compile(r"Dynamic SQL Error"),
        re.compile(r"Warning.*?\Wibase_"),
        re.compile(r"org\.firebirdsql\.jdbc"),
        re.compile(r"Pdo[./_\\]Firebird"),

    ],
    "SQLite": [
        re.compile(r"SQLite/JDBCDriver"),
        re.compile(r"SQLite\.Exception"),
        re.compile(r"(Microsoft|System)\.Data\.SQLite\.SQLiteException"),
        re.compile(r"Warning.*?\W(sqlite_|SQLite3::)"),
        re.compile(r"\[SQLITE_ERROR\]"),
        re.compile(r"Error: SQLITE_ERROR:"),  # OWASP Juice Shop
        re.compile(r"SQLite error \d+:"),
        re.compile(r"sqlite3.OperationalError:"),
        re.compile(r"SQLite3::SQLException"),
        re.compile(r"org\.sqlite\.JDBC"),
        re.compile(r"Pdo[./_\\]Sqlite"),
        re.compile(r"SQLiteException"),
    ],
    "SAP MaxDB": [
        re.compile(r"SQL error.*?POS([0-9]+)"),
        re.compile(r"Warning.*?\Wmaxdb_"),
        re.compile(r"DriverSapDB"),
        re.compile(r"-3014.*?Invalid end of SQL statement"),
        re.compile(r"com\.sap\.dbtech\.jdbc"),
        re.compile(r"\[-3008\].*?: Invalid keyword or missing delimiter"),
    ],
    "Sybase": [
        re.compile(r"Warning.*?\Wsybase_"),
        re.compile(r"Sybase message"),
        re.compile(r"Sybase.*?Server message"),
        re.compile(r"SybSQLException"),
        re.compile(r"Sybase\.Data\.AseClient"),
        re.compile(r"com\.sybase\.jdbc"),
    ],
    "Ingres": [
        re.compile(r"Warning.*?\Wingres_"),
        re.compile(r"Ingres SQLSTATE"),
        re.compile(r"Ingres\W.*?Driver"),
        re.compile(r"com\.ingres\.gcf\.jdbc"),
    ],
    "FrontBase": [
        re.compile(r"Exception (condition )?\d+\. Transaction rollback"),
        re.compile(r"com\.frontbase\.jdbc"),
        re.compile(r"Syntax error 1. Missing"),
        re.compile(r"(Semantic|Syntax) error [1-4]\d{2}\."),
    ],
    "HSQLDB": [
        re.compile(r"Unexpected end of command in statement \["),
        re.compile(r"Unexpected token.*?in statement \["),
        re.compile(r"org\.hsqldb\.jdbc"),
    ],
    "H2": [
        re.compile(r"org\.h2\.jdbc"),
        re.compile(r"\[42000-192\]"),
    ],
    "MonetDB": [
        re.compile(r"![0-9]{5}![^\n]+(failed|unexpected|error|syntax|expected|violation|exception)"),
        re.compile(r"\[MonetDB\]\[ODBC Driver"),
        re.compile(r"nl\.cwi\.monetdb\.jdbc"),
    ],
    "Apache Derby": [
        re.compile(r"Syntax error: Encountered"),
        re.compile(r"org\.apache\.derby"),
        re.compile(r"ERROR 42X01"),
    ],
    "Vertica": [
        re.compile(r", Sqlstate: (3F|42).{3}, (Routine|Hint|Position):"),
        re.compile(r"/vertica/Parser/scan"),
        re.compile(r"com\.vertica\.jdbc"),
        re.compile(r"org\.jkiss\.dbeaver\.ext\.vertica"),
        re.compile(r"com\.vertica\.dsi\.dataengine"),
    ],
    "Mckoi": [
        re.compile(r"com\.mckoi\.JDBCDriver"),
        re.compile(r"com\.mckoi\.database\.jdbc"),
        re.compile(r"&lt;REGEX_LITERAL&gt;"),
    ],
    "Presto": [
        re.compile(r"com\.facebook\.presto\.jdbc"),
        re.compile(r"io\.prestosql\.jdbc"),
        re.compile(r"com\.simba\.presto\.jdbc"),
        re.compile(r"UNION query has different number of fields: \d+, \d+"),
    ],
    "Altibase": [
        re.compile(r"Altibase\.jdbc\.driver")
    ],
    "MimerSQL": [
        re.compile(r"com\.mimer\.jdbc"),
        re.compile(r"Syntax error,[^\n]+assumed to mean"),
    ],
    "CrateDB": [
        re.compile(r"io\.crate\.client\.jdbc"),
    ],
    "Cache": [
        re.compile(r"encountered after end of query"),
        re.compile(r"A comparison operator is required here"),
    ]
}

def url_detection(url, payloads, session):
    if '?' in url:
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
            
        for payload in payloads:
            if query_params is not None:  # 추가된 None 체크
                for params in query_params:
                    query_params[params] = payload
                update_query_string = urlencode(query_params, doseq=True)
                payload_url = parsed_url._replace(query=update_query_string).geturl()
                get_response = session.get(payload_url)
                    
                for dbms, regex_list in DBMS_ERROR_PATTERNS.items():
                    for regex in regex_list:
                        if regex.search(get_response.text):
                            print(f"{url}: {dbms} 취약점 발견1")
                            return url
            else:
            
                for payload in payloads:
                    payload_url = url + payload
                    get_response = session.get(payload_url)

                    for dbms, regex_list in DBMS_ERROR_PATTERNS.items():
                        for regex in regex_list:
                            if regex.search(get_response.text):
                                print(f"{url}: {dbms} 취약점 발견2")
                                return url

    else:
        for payload in payloads:
            payload_url = url + '?' + payload
            get_response = session.get(payload_url)
                    
            for dbms, regex_list in DBMS_ERROR_PATTERNS.items():
                for regex in regex_list:
                    if regex.search(get_response.text):
                        print(f"{url}: {dbms} 취약점 발견")
                        return url
    
    return

def form_detected(url, forms, payloads, session):
    pass_pattern = re.compile(r'\bpassword\b', re.IGNORECASE)
    update_payload = {}
    vulnerable_urls = []

    for form in forms:
        # 폼 액션 URL과 전송 방식 가져오기
        form_action = form.get("action")
        if form_action is None:
            form_action = url
        else:
            form_action = urljoin(url, form_action)

        vulnerable_urls.append(url_detection(form_action, payloads, session))

        form_method = form.get("method")
        if form_method is None:
            form_method = "get"

        if form_method.lower() == "get":
            input_data = {}
            for input_field in form.find_all("input"):
                input_data[input_field.get("name")] = input_field.get("type")
                
            for payload in payloads:
                for name in input_data:
                    if input_data[name] != 'submit':
                        if pass_pattern.search(input_data[name]):
                            update_payload[name] = 'swu_canner'
                        else:
                            update_payload[name] = payload
                            
                get_response = session.get(form_action, params=update_payload)
                if 'logout' in get_response.text.lower():
                    print(f'{form_action}: SQL 취약점 발견3')
                    vulnerable_urls.append(form_action)
                else:
                    for dbms, regex_list in DBMS_ERROR_PATTERNS.items():
                        for regex in regex_list:
                            if regex.search(get_response.text):
                                print(f"{form_action}: {dbms} 취약점 발견4")
                                vulnerable_urls.append(form_action)


        # POST 방식으로 폼 요청 처리
        elif form_method.lower() == "post":
            input_data = {}
            for input_field in form.find_all("input"):
                input_data[input_field.get("name")] = input_field.get("type")
                
            for payload in payloads:
                for name in input_data:
                    if input_data[name] != 'submit':
                        if pass_pattern.search(input_data[name]):
                            update_payload[name] = 'swu_canner'
                        else:
                            update_payload[name] = payload
                            
                de_response = session.post(form_action, data=update_payload)

                de_soup = BeautifulSoup(de_response.text, 'html.parser')
                all_links = de_soup.find_all('a')
                logout_links = [link for link in all_links if 'logout' in str(link).lower()]

                if logout_links:
                    print(f'{form_action}: SQL 취약점 발견5')
                    vulnerable_urls.append(form_action)
                else:
                    for dbms, regex_list in DBMS_ERROR_PATTERNS.items():
                        for regex in regex_list:
                            if regex.search(de_response.text):
                                print(f"{form_action}: {dbms} 취약점 발견6")
                                vulnerable_urls.append(form_action)
        

    return vulnerable_urls

def sql_injection_detection(url, vulnerabilities):
    logger.info("Starting SQL Injection detection...")

    fname = "blog\payloads\sql.txt"
    with open(fname) as f:
        content = f.readlines()
    payloads = [x.strip() for x in content]

    vuln_url = []

    # 세션 시작
    session = requests.Session()

    response = session.get(url)
    soup = BeautifulSoup(response.text, "html.parser")

    vulnerable_urls = url_detection(url, payloads, session)
    if vulnerable_urls:
        vuln_url.append(vulnerable_urls)

    # 폼 요소 찾기
    forms = soup.find_all("form")

    if forms:
        vulnerable_urls = form_detected(url, forms, payloads, session)
        if vulnerable_urls:
            vuln_url.extend(vulnerable_urls)

    if None in vuln_url:
        vuln_url.remove(None)
    
    if vuln_url:
        for url in vuln_url:
            split_url = urlsplit(url)
            no_query_url = urlunsplit((split_url.scheme, split_url.netloc, split_url.path, '', ''))
            vulnerabilities.append(no_query_url)


    logger.info("Finished SQL Injection detection.")