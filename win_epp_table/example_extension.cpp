/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <osquery/sdk.h>
#include <osquery/system.h>

using namespace osquery;

#define FILE_SHARE_VALID_FLAGS (FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE)
#define WIN_MBR_TABLE "win_mbr_table"

class ExampleConfigPlugin : public ConfigPlugin {
 public:
  Status setUp() {
    LOG(WARNING) << "ExampleConfigPlugin setting up";
    return Status(0, "OK");
  }

  Status genConfig(std::map<std::string, std::string>& config) {
    config["data"] = "{\"queries\":{}}";
    return Status(0, "OK");
  }
};

class ExampleTable : public TablePlugin {
 private:
  TableColumns columns() const {
    return {
        std::make_tuple("example_text", TEXT_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple(
            "example_integer", INTEGER_TYPE, ColumnOptions::DEFAULT),
    };
  }

  QueryData generate(QueryContext& request) {
    QueryData results;

    Row r;
    r["example_text"] = "example";
    r["example_integer"] = INTEGER(1);

    results.push_back(r);
    return results;
  }
};

/**
 * @brief A more 'complex' example table is provided to assist with tests.
 *
 * This table will access options and flags known to the extension.
 * An extension should not assume access to any CLI flags- rather, access is
 * provided via the osquery-meta table: osquery_flags.
 *
 * There is no API/C++ wrapper to provide seamless use of flags yet.
 * We can force an implicit query to the manager though.
 *
 * Database access should be mediated by the *Database functions.
 * Direct use of the "database" registry will lead to undefined behavior.
 */
class ComplexExampleTable : public TablePlugin {
 private:
  TableColumns columns() const {
    return {
        std::make_tuple("flag_test", TEXT_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple("database_test", TEXT_TYPE, ColumnOptions::DEFAULT),
    };
  }

  QueryData generate(QueryContext& request) {
    Row r;

    // Use the basic 'force' flag to check implicit SQL usage.
    auto flags =
        SQL("select default_value from osquery_flags where name = 'force'");
    if (flags.rows().size() > 0) {
      r["flag_test"] = flags.rows().back().at("default_value");
    }

    std::string content;
    setDatabaseValue(kPersistentSettings, "complex_example", "1");
    if (getDatabaseValue(kPersistentSettings, "complex_example", content)) {
      r["database_test"] = content;
    }

    return {r};
  }
};


class MasterBootRecordTable : public TablePlugin {
  private:
   TableColumns columns() const {
    return {
        std::make_tuple("disk_name", TEXT_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple(
            "mbr_chksum", BIGINT_TYPE, ColumnOptions::DEFAULT),
    };
  }
  short ReadSect(const char* dsk, char*& buff, unsigned int nsect)
{
	 DWORD dwRead;
	 HANDLE hDisk = CreateFile(dsk, GENERIC_READ, FILE_SHARE_VALID_FLAGS, 0, OPEN_EXISTING, 0, 0);
	 if(hDisk == INVALID_HANDLE_VALUE)
	 {
		 CloseHandle(hDisk);
		 return 1;
	 }
	 SetFilePointer(hDisk, nsect*512, 0, FILE_BEGIN);
	 ReadFile(hDisk, buff, 512, &dwRead, 0);
	 CloseHandle(hDisk);
	 return 0;
}

unsigned long getChecksum(char* buff, int n)
{
	long XOR;
	std::string output;
	for (int i = 0; i < n; i++) {
		XOR ^= buff[i];
	}
	return XOR;
}

QueryData generate(QueryContext& context) {
  Row r;

  char *dsk = "C:\\";
  int sector = 0;

  char *buff = new char[512];
  ReadSect(dsk, buff, sector);

  
  r["disk_name"] = dsk;
  r["mbr_chksum"] = BIGINT(getChecksum(buff, 512));

  return { r };
}
};

REGISTER_EXTERNAL(ExampleConfigPlugin, "config", "example");
REGISTER_EXTERNAL(ExampleTable, "table", "example");
REGISTER_EXTERNAL(ComplexExampleTable, "table", "complex_example");
REGISTER_EXTERNAL(MasterBootRecordTable, "table", WIN_MBR_TABLE);

int main(int argc, char* argv[]) {
  osquery::Initializer runner(argc, argv, ToolType::EXTENSION);

  auto status = startExtension("example", "0.0.1");
  if (!status.ok()) {
    LOG(ERROR) << status.getMessage();
    runner.requestShutdown(status.getCode());
  }

  // Finally wait for a signal / interrupt to shutdown.
  runner.waitForShutdown();
  return 0;
}
