# osq-ext
PolyLogyx repostiory of osquery Extensions. (under construction)

This repository contains the extensions to osquery on Windows platform

To know more about osquery, visit: https://osquery.io/

To know more about osquery extensions, visit: https://osquery.readthedocs.io/en/stable/development/osquery-sdk/


win_epp_table
-------------

The table provides the state and status of the endpoint protection software running on the end point.

osquery> select * from win_epp_table;
+--------------+------------------+---------------+--------------------+
| product_type | product_name     | product_state | product_signatures |
+--------------+------------------+---------------+--------------------+
| Anti-Virus   | Windows Defender | On            | Up-to-date         |
| Anti-Spyware | Windows Defender | On            | Up-to-date         |
| Firewall     | Windows Firewall | On            | Not Applicable     |
+--------------+------------------+---------------+--------------------+
osquery>

It has been tested with all the major endpoint protection products. The code is based on the original code from Microsoft, published at
